#!/usr/bin/env python3
"""
Offline test harness for the Control Tower pre-upgrade precheck.

WHY THIS EXISTS
---------------
A live run against a *healthy* landing zone only proves the PASS/INFO paths. It does NOT
prove that the checks correctly raise BLOCKER / WARNING on a broken environment. This harness
feeds each check simulated "bad" (and "good") AWS API responses via lightweight fakes and
asserts the correct severity fires — so the blocker-detection logic is proven without needing
a deliberately-broken real Control Tower account.

RUN
---
    python3 tests/test_blocker_paths.py            # plain unittest, no extra deps
    (or)  python3 -m pytest tests/                 # if pytest is installed

No AWS credentials or network are used.
"""

import importlib.util
import os
import sys
import unittest
from unittest import mock

from botocore.exceptions import ClientError

# ---- import the tool module by path (Source/ct_preupgrade_precheck.py) --------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_MOD_PATH = os.path.join(_HERE, "..", "Source", "ct_preupgrade_precheck.py")
_spec = importlib.util.spec_from_file_location("ct_precheck", _MOD_PATH)
ct = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ct)


# ---- fakes ---------------------------------------------------------------------------
def client_error(code, op="Op"):
    return ClientError({"Error": {"Code": code, "Message": code}}, op)


class FakeClient:
    """A stand-in boto3 client. `responses` maps method_name -> dict (or callable(**kwargs)).
    `errors` maps method_name -> exception to raise. can_paginate() returns False so the
    tool's _collect() falls back to a direct method call."""

    def __init__(self, responses=None, errors=None):
        self.responses = responses or {}
        self.errors = errors or {}

    def can_paginate(self, op):
        return False

    def __getattr__(self, name):
        # only reached for names not set as real attributes (i.e., API calls)
        def _call(**kwargs):
            if name in self.errors:
                raise self.errors[name]
            r = self.responses.get(name, {})
            return r(**kwargs) if callable(r) else r
        return _call


class _Creds:
    access_key = "AK"
    secret_key = "SK"
    token = "TK"

    def get_frozen_credentials(self):
        return self


class FakeSession:
    def __init__(self, clients):
        self._clients = clients

    def client(self, service, region_name=None):
        return self._clients.get(service, FakeClient())

    def get_credentials(self):
        return _Creds()


def make_ctx(clients=None, **overrides):
    """Build a Context wired to fakes, with healthy discovered defaults that tests override."""
    clients = clients or {}
    clients.setdefault("controltower", FakeClient())
    clients.setdefault("organizations", FakeClient())
    ctx = ct.Context(FakeSession(clients), "us-east-1", "AWSControlTowerExecution")
    ctx.mgmt_account = "111111111111"
    ctx.lz = overrides.get("lz", {
        "status": "ACTIVE", "version": "3.2", "latestAvailableVersion": "4.0",
        "driftStatus": {"status": "IN_SYNC"},
    })
    ctx.manifest = overrides.get("manifest", {})
    ctx.governed_regions = overrides.get("governed_regions", ["us-east-1"])
    ctx.audit_account = overrides.get("audit_account", "547106939137")
    ctx.log_archive_account = overrides.get("log_archive_account", "944915248067")
    ctx.kms_key_arn = overrides.get("kms_key_arn", None)
    return ctx


def levels(report):
    return {f.level for f in report.findings}


def _run(check, ctx):
    rpt = ct.Report()
    check(ctx, rpt)
    return rpt


# ---- tests ---------------------------------------------------------------------------
class TestBlockerPaths(unittest.TestCase):

    # 1. LZ status -----------------------------------------------------------------
    def test_lz_status_failed_blocks(self):
        ctx = make_ctx(lz={"status": "FAILED", "version": "3.2", "messages": [{"message": "boom"}]})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_lz_status, ctx)))

    def test_lz_status_processing_blocks(self):
        ctx = make_ctx(lz={"status": "PROCESSING", "version": "3.2"})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_lz_status, ctx)))

    def test_lz_status_active_passes(self):
        ctx = make_ctx()
        self.assertIn(ct.PASS, levels(_run(ct.check_lz_status, ctx)))

    # 2. LZ drift ------------------------------------------------------------------
    def test_lz_drift_drifted_blocks(self):
        ctx = make_ctx(lz={"status": "ACTIVE", "driftStatus": {"status": "DRIFTED"}})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_lz_drift, ctx)))

    def test_lz_drift_in_sync_passes(self):
        ctx = make_ctx()
        self.assertIn(ct.PASS, levels(_run(ct.check_lz_drift, ctx)))

    # 4. managed accounts ----------------------------------------------------------
    def test_managed_accounts_suspended_warns(self):
        orgs = FakeClient({"list_accounts": {"Accounts": [
            {"Id": "222222222222", "Name": "bad", "Status": "SUSPENDED"}]}})
        ctx = make_ctx({"organizations": orgs})
        self.assertIn(ct.WARNING, levels(_run(ct.check_managed_accounts, ctx)))

    # 5. suspended account + provisioned product (classic blocker) -----------------
    def test_suspended_with_provisioned_product_blocks(self):
        orgs = FakeClient({"list_accounts": {"Accounts": [
            {"Id": "333333333333", "Name": "closed", "Status": "SUSPENDED"}]}})
        sc = FakeClient({"search_provisioned_products": {"ProvisionedProducts": [
            {"Name": "account-333333333333-abc", "Status": "AVAILABLE",
             "PhysicalId": "arn:aws:...:333333333333"}]}})
        ctx = make_ctx({"organizations": orgs, "servicecatalog": sc})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_suspended_with_provisioned_product, ctx)))

    # 6. enabled controls drift ----------------------------------------------------
    def test_enabled_controls_drift_blocks(self):
        orgs = FakeClient({
            "list_roots": {"Roots": [{"Id": "r-root"}]},
            "list_organizational_units_for_parent":
                lambda ParentId=None, **k: {"OrganizationalUnits":
                    [{"Id": "ou-1", "Arn": "arn:ou-1", "Name": "Prod"}] if ParentId == "r-root" else []},
        })
        ctl = FakeClient({"list_enabled_controls": {"enabledControls": [
            {"controlIdentifier": "AWS-GR_X",
             "driftStatusSummary": {"driftStatus": "DRIFTED"},
             "statusSummary": {"status": "SUCCEEDED"}}]}})
        ctx = make_ctx({"organizations": orgs, "controltower": ctl})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_enabled_controls, ctx)))

    # 7. enabled baselines drift/failed --------------------------------------------
    def test_enabled_baselines_failed_blocks(self):
        ctl = FakeClient({"list_enabled_baselines": {"enabledBaselines": [
            {"targetIdentifier": "arn:acct", "baselineVersion": "4.0",
             "statusSummary": {"status": "FAILED"}}]}})
        ctx = make_ctx({"controltower": ctl})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_enabled_baselines, ctx)))

    # 8. StackSets: INOPERABLE blocks; OUTDATED is INFO ----------------------------
    def test_stacksets_inoperable_in_shared_blocks(self):
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerBP-BASELINE-CONFIG"}]},
            "list_stack_instances": {"Summaries": [
                {"Account": "111111111111", "Region": "us-east-1", "Status": "INOPERABLE",
                 "DriftStatus": "NOT_CHECKED"}]},
        })
        # make_ctx sets mgmt_account = 111111111111 (a shared account)
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_stacksets, ctx)))

    def test_stacksets_member_drift_warns_not_blocks(self):
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerBP-BASELINE-ROLES"}]},
            "list_stack_instances": {"Summaries": [
                {"Account": "222222222222", "Region": "us-east-1", "Status": "CURRENT",
                 "DriftStatus": "DRIFTED"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [
            {"Id": "111111111111", "Status": "ACTIVE"},
            {"Id": "222222222222", "Status": "ACTIVE"}]}})  # 222... is a member (not shared)
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        lv = levels(_run(ct.check_stacksets, ctx))
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_stacksets_outdated_is_info_not_blocker(self):
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerBP-BASELINE-CONFIG"}]},
            "list_stack_instances": {"Summaries": [
                {"Account": "1", "Region": "us-east-1", "Status": "OUTDATED",
                 "DriftStatus": "NOT_CHECKED"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "1", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        lv = levels(_run(ct.check_stacksets, ctx))
        self.assertIn(ct.INFO, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_stacksets_drifted_in_shared_blocks(self):
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerBP-BASELINE-ROLES"}]},
            "list_stack_instances": {"Summaries": [
                {"Account": "111111111111", "Region": "us-east-1", "Status": "CURRENT",
                 "DriftStatus": "DRIFTED"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_stacksets, ctx)))

    def test_stacksets_orphaned_account_not_blocker(self):
        # A FAILED/INOPERABLE instance for an account that has LEFT the org is a
        # stale StackSet leftover: it must be INFO (cleanup), never a BLOCKER,
        # because a landing-zone update does not act on departed accounts.
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerExecutionRole"}]},
            "list_stack_instances": {"Summaries": [
                {"Account": "999999999999", "Region": "us-east-1", "Status": "OUTDATED",
                 "StackInstanceStatus": {"DetailedStatus": "FAILED"},
                 "DriftStatus": "NOT_CHECKED"}]},
        })
        # Org does NOT contain 999999999999.
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        lv = levels(_run(ct.check_stacksets, ctx))
        self.assertIn(ct.INFO, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    # 8b. Active StackSet drift detection (opt-in --detect-drift) ------------------
    def test_active_drift_skipped_when_disabled(self):
        ctx = make_ctx()  # detect_drift defaults False
        lv = levels(_run(ct.check_stackset_active_drift, ctx))
        self.assertIn(ct.INFO, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_active_drift_detects_drift_blocks(self):
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerExecutionRole"}]},
            "detect_stack_set_drift": {"OperationId": "op-1"},
            "describe_stack_set_operation": {"StackSetOperation": {"Status": "SUCCEEDED"}},
            "list_stack_instances": {"Summaries": [
                {"Account": "111111111111", "Region": "us-east-1", "Status": "CURRENT",
                 "DriftStatus": "DRIFTED"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})  # 111... is mgmt (shared)
        ctx.detect_drift = True
        lv = levels(_run(ct.check_stackset_active_drift, ctx))
        self.assertIn(ct.BLOCKER, lv)

    def test_active_drift_member_warns_not_blocks(self):
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerExecutionRole"}]},
            "detect_stack_set_drift": {"OperationId": "op-1"},
            "describe_stack_set_operation": {"StackSetOperation": {"Status": "SUCCEEDED"}},
            "list_stack_instances": {"Summaries": [
                {"Account": "222222222222", "Region": "us-east-1", "Status": "CURRENT",
                 "DriftStatus": "DRIFTED"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [
            {"Id": "111111111111", "Status": "ACTIVE"},
            {"Id": "222222222222", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        ctx.detect_drift = True
        ctx.assume = lambda a, r, s: FakeClient({"describe_stack_resource_drifts":
                                                 {"StackResourceDrifts": []}})
        lv = levels(_run(ct.check_stackset_active_drift, ctx))
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_active_drift_orphaned_drift_not_blocker(self):
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerExecutionRole"}]},
            "detect_stack_set_drift": {"OperationId": "op-1"},
            "describe_stack_set_operation": {"StackSetOperation": {"Status": "SUCCEEDED"}},
            "list_stack_instances": {"Summaries": [
                {"Account": "999999999999", "Region": "us-east-1", "Status": "CURRENT",
                 "DriftStatus": "DRIFTED"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "1", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        ctx.detect_drift = True
        lv = levels(_run(ct.check_stackset_active_drift, ctx))
        self.assertNotIn(ct.BLOCKER, lv)
        self.assertIn(ct.INFO, lv)

    def test_active_drift_reports_resource_detail(self):
        member = FakeClient({"describe_stack_resource_drifts": {"StackResourceDrifts": [
            {"LogicalResourceId": "AWSControlTowerExecutionRole", "ResourceType": "AWS::IAM::Role",
             "StackResourceDriftStatus": "MODIFIED",
             "PropertyDifferences": [{"PropertyPath": "/AssumeRolePolicyDocument"}]}]}})
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerExecutionRole"}]},
            "detect_stack_set_drift": {"OperationId": "op-1"},
            "describe_stack_set_operation": {"StackSetOperation": {"Status": "SUCCEEDED"}},
            "list_stack_instances": {"Summaries": [
                {"Account": "111111111111", "Region": "us-east-1", "Status": "CURRENT", "DriftStatus": "DRIFTED",
                 "StackId": "arn:aws:cloudformation:us-east-1:1:stack/foo/abc"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        ctx.detect_drift = True
        ctx.assume = lambda a, r, s: member
        rpt = _run(ct.check_stackset_active_drift, ctx)
        blk = [f for f in rpt.findings if f.level == ct.BLOCKER][0]
        self.assertIn("AWS::IAM::Role/AWSControlTowerExecutionRole:MODIFIED", blk.rows[0][-1])

    def test_active_drift_role_missing_points_to_stack(self):
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerExecutionRole"}]},
            "detect_stack_set_drift": {"OperationId": "op-1"},
            "describe_stack_set_operation": {"StackSetOperation": {"Status": "SUCCEEDED"}},
            "list_stack_instances": {"Summaries": [
                {"Account": "111111111111", "Region": "us-east-1", "Status": "CURRENT", "DriftStatus": "DRIFTED",
                 "StackId": "arn:aws:cloudformation:us-east-1:1:stack/foo/abc"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        ctx.detect_drift = True
        def _boom(a, r, s):
            raise RuntimeError("no such role")
        ctx.assume = _boom
        rpt = _run(ct.check_stackset_active_drift, ctx)
        self.assertIn(ct.BLOCKER, levels(rpt))
        blk = [f for f in rpt.findings if f.level == ct.BLOCKER][0]
        self.assertIn("inspect stack", blk.rows[0][-1])

    def test_stacksets_drift_deduped_when_detect_drift(self):
        # With --detect-drift on, the base check must NOT also flag persisted DRIFTED
        # (the active drift check owns drift) -> no duplicate blocker.
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerExecutionRole"}]},
            "list_stack_instances": {"Summaries": [
                {"Account": "111111111111", "Region": "us-east-1", "Status": "CURRENT",
                 "DriftStatus": "DRIFTED"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        ctx.detect_drift = True
        lv = levels(_run(ct.check_stacksets, ctx))
        self.assertNotIn(ct.BLOCKER, lv)

    # 8c. Org all-features -----------------------------------------------------------
    def test_org_consolidated_billing_blocks(self):
        orgs = FakeClient({"describe_organization": {"Organization": {"FeatureSet": "CONSOLIDATED_BILLING"}}})
        ctx = make_ctx({"organizations": orgs})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_org_all_features, ctx)))

    def test_org_all_features_passes(self):
        orgs = FakeClient({"describe_organization": {"Organization": {"FeatureSet": "ALL"}}})
        ctx = make_ctx({"organizations": orgs})
        self.assertIn(ct.PASS, levels(_run(ct.check_org_all_features, ctx)))

    # 8d. In-progress StackSet operations --------------------------------------------
    def test_stackset_ops_in_progress_blocks(self):
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerBP-BASELINE-CONFIG"}]},
            "list_stack_set_operations": {"Summaries": [
                {"Action": "UPDATE", "Status": "RUNNING", "OperationId": "op-1"}]},
        })
        ctx = make_ctx({"cloudformation": cfn})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_stackset_operations_in_progress, ctx)))

    def test_stackset_ops_idle_passes(self):
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerBP-BASELINE-CONFIG"}]},
            "list_stack_set_operations": {"Summaries": [
                {"Action": "UPDATE", "Status": "SUCCEEDED", "OperationId": "op-0"}]},
        })
        ctx = make_ctx({"cloudformation": cfn})
        lv = levels(_run(ct.check_stackset_operations_in_progress, ctx))
        self.assertIn(ct.PASS, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    # 8e. Account Factory provisioned-product health ---------------------------------
    def test_provisioned_product_tainted_blocks(self):
        sc = FakeClient({"search_provisioned_products": {"ProvisionedProducts": [
            {"Name": "acct-x", "Status": "TAINTED", "Type": "CONTROL_TOWER_ACCOUNT"}]}})
        ctx = make_ctx({"servicecatalog": sc})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_provisioned_product_health, ctx)))

    def test_provisioned_product_under_change_warns(self):
        sc = FakeClient({"search_provisioned_products": {"ProvisionedProducts": [
            {"Name": "acct-y", "Status": "UNDER_CHANGE", "Type": "CONTROL_TOWER_ACCOUNT"}]}})
        ctx = make_ctx({"servicecatalog": sc})
        lv = levels(_run(ct.check_provisioned_product_health, ctx))
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_provisioned_product_available_passes(self):
        sc = FakeClient({"search_provisioned_products": {"ProvisionedProducts": [
            {"Name": "acct-z", "Status": "AVAILABLE", "Type": "CONTROL_TOWER_ACCOUNT"}]}})
        ctx = make_ctx({"servicecatalog": sc})
        self.assertIn(ct.PASS, levels(_run(ct.check_provisioned_product_health, ctx)))

    # 8f. STS AccessDenied must not be a false "region disabled" blocker -------------
    def test_sts_access_denied_is_unknown_not_blocker(self):
        ctx = make_ctx()
        ctx.governed_regions = ["us-east-1"]
        with mock.patch.object(
                ct.boto3, "client",
                return_value=FakeClient(errors={"get_caller_identity": client_error("AccessDenied")})):
            lv = levels(_run(ct.check_sts_regional_activation, ctx))
        self.assertIn(ct.UNKNOWN, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_sts_region_disabled_blocks(self):
        ctx = make_ctx()
        ctx.governed_regions = ["ap-east-1"]
        with mock.patch.object(
                ct.boto3, "client",
                return_value=FakeClient(errors={"get_caller_identity": client_error("RegionDisabledException")})):
            lv = levels(_run(ct.check_sts_regional_activation, ctx))
        self.assertIn(ct.BLOCKER, lv)

    # 9. Config in shared accounts: extra recorder warns; unreachable = UNKNOWN ----
    def test_config_extra_recorder_warns(self):
        ctx = make_ctx()
        ctx.assume = lambda a, r, s: FakeClient({
            "describe_configuration_recorders": {"ConfigurationRecorders": [{}, {}]}})
        self.assertIn(ct.WARNING, levels(_run(ct.check_config_in_shared_accounts, ctx)))

    def test_config_unreachable_is_unknown_not_pass(self):
        ctx = make_ctx()
        def boom(a, r, s):
            raise client_error("AccessDenied", "AssumeRole")
        ctx.assume = boom
        self.assertIn(ct.UNKNOWN, levels(_run(ct.check_config_in_shared_accounts, ctx)))

    def test_config_no_shared_ids_is_unknown(self):
        ctx = make_ctx(audit_account=None, log_archive_account=None)
        self.assertIn(ct.UNKNOWN, levels(_run(ct.check_config_in_shared_accounts, ctx)))

    # 11. trusted access missing ---------------------------------------------------
    def test_trusted_access_missing_blocks(self):
        orgs = FakeClient({"list_aws_service_access_for_organization":
                           {"EnabledServicePrincipals": [{"ServicePrincipal": "sso.amazonaws.com"}]}})
        ctx = make_ctx({"organizations": orgs})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_trusted_access, ctx)))

    def test_trusted_access_present_passes(self):
        orgs = FakeClient({"list_aws_service_access_for_organization":
                           {"EnabledServicePrincipals":
                            [{"ServicePrincipal": s} for s in ct._REQUIRED_TRUSTED_SERVICES]}})
        ctx = make_ctx({"organizations": orgs})
        self.assertIn(ct.PASS, levels(_run(ct.check_trusted_access, ctx)))

    # 13. required IAM roles missing -----------------------------------------------
    def test_required_roles_missing_blocks(self):
        iam = FakeClient(errors={"get_role": client_error("NoSuchEntity", "GetRole")})
        ctx = make_ctx()
        ctx.session._clients["iam"] = iam
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_required_iam_roles, ctx)))

    def test_required_roles_present_passes(self):
        iam = FakeClient({"get_role": {"Role": {"RoleName": "x"}}})
        ctx = make_ctx()
        ctx.session._clients["iam"] = iam
        self.assertIn(ct.PASS, levels(_run(ct.check_required_iam_roles, ctx)))

    # 14. KMS key ------------------------------------------------------------------
    def test_kms_disabled_blocks(self):
        kms = FakeClient({"describe_key": {"KeyMetadata": {"KeyState": "PendingDeletion"}}})
        ctx = make_ctx({"kms": kms}, kms_key_arn="arn:aws:kms:us-east-1:1:key/abc")
        ctx.session._clients["kms"] = kms
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_kms_key, ctx)))

    def test_kms_enabled_passes(self):
        kms = FakeClient({"describe_key": {"KeyMetadata": {"KeyState": "Enabled"}}})
        ctx = make_ctx(kms_key_arn="arn:aws:kms:us-east-1:1:key/abc")
        ctx.session._clients["kms"] = kms
        self.assertIn(ct.PASS, levels(_run(ct.check_kms_key, ctx)))

    def test_kms_none_is_info(self):
        ctx = make_ctx(kms_key_arn=None)
        self.assertIn(ct.INFO, levels(_run(ct.check_kms_key, ctx)))

    # 15. STS regional activation --------------------------------------------------
    def test_sts_region_disabled_blocks(self):
        fake_sts = FakeClient(errors={"get_caller_identity":
                                      client_error("RegionDisabledException", "GetCallerIdentity")})
        ctx = make_ctx(governed_regions=["us-east-1", "ap-east-1"])
        with mock.patch.object(ct.boto3, "client", return_value=fake_sts):
            self.assertIn(ct.BLOCKER, levels(_run(ct.check_sts_regional_activation, ctx)))

    def test_sts_all_active_passes(self):
        fake_sts = FakeClient({"get_caller_identity": {"Account": "1"}})
        ctx = make_ctx(governed_regions=["us-east-1"])
        with mock.patch.object(ct.boto3, "client", return_value=fake_sts):
            self.assertIn(ct.PASS, levels(_run(ct.check_sts_regional_activation, ctx)))

    # 16. SCP headroom at 10-limit -------------------------------------------------
    def test_scp_at_limit_warns(self):
        ten = [{"Name": f"p{i}", "Id": f"p-{i}", "AwsManaged": False} for i in range(10)]
        orgs = FakeClient({
            "list_roots": {"Roots": [{"Id": "r-root"}]},
            "list_organizational_units_for_parent": lambda ParentId=None, **k: {"OrganizationalUnits": []},
            "list_policies_for_target": {"Policies": ten},
        })
        ctx = make_ctx({"organizations": orgs})
        self.assertIn(ct.WARNING, levels(_run(ct.check_scp_headroom, ctx)))

    # 17. SCP blocking content -----------------------------------------------------
    def test_scp_deny_without_ct_exemption_warns(self):
        orgs = FakeClient({
            "list_roots": {"Roots": [{"Id": "r-root"}]},
            "list_organizational_units_for_parent": lambda ParentId=None, **k: {"OrganizationalUnits": []},
            # customer SCP attached, and FullAWSAccess NOT present
            "list_policies_for_target": {"Policies": [
                {"Name": "restrict-ec2", "Id": "p-restrict", "AwsManaged": False}]},
            "describe_policy": {"Policy": {"Content":
                '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ec2:*","Resource":"*"}]}'}},
        })
        ctx = make_ctx({"organizations": orgs})
        # both the missing-FullAWSAccess and the risky-Deny should raise WARNING
        self.assertIn(ct.WARNING, levels(_run(ct.check_scp_blocking, ctx)))

    def test_scp_deny_with_ct_exemption_and_fullaccess_passes(self):
        orgs = FakeClient({
            "list_roots": {"Roots": [{"Id": "r-root"}]},
            "list_organizational_units_for_parent": lambda ParentId=None, **k: {"OrganizationalUnits": []},
            "list_policies_for_target": {"Policies": [
                {"Name": "FullAWSAccess", "Id": "p-Full", "AwsManaged": True},
                {"Name": "restrict-ec2", "Id": "p-restrict", "AwsManaged": False}]},
            "describe_policy": {"Policy": {"Content":
                '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ec2:*","Resource":"*",'
                '"Condition":{"ArnNotLike":{"aws:PrincipalARN":'
                '"arn:aws:iam::*:role/AWSControlTowerExecution"}}}]}'}},
        })
        ctx = make_ctx({"organizations": orgs})
        self.assertIn(ct.PASS, levels(_run(ct.check_scp_blocking, ctx)))

    # 10. customizations detected --------------------------------------------------
    def test_customizations_detected_info(self):
        cfn = FakeClient({
            "list_stacks": {"StackSummaries": [
                {"StackName": "CustomControlTower-abc", "StackStatus": "CREATE_COMPLETE"}]},
            "list_stack_sets": {"Summaries": [{"StackSetName": "CustomControlTower-stackset-1"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "1", "Name": "AFTmanagement"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        self.assertIn(ct.INFO, levels(_run(ct.check_customizations, ctx)))

    # preflight: too-old SDK is a clean BLOCKER, not a crash -----------------------
    def test_old_sdk_preflight_blocks_cleanly(self):
        class NoLZClient(FakeClient):
            # simulate an old SDK that lacks list_landing_zones
            def __getattr__(self, name):
                if name == "list_landing_zones":
                    raise AttributeError(name)
                return super().__getattr__(name)
        sess = FakeSession({"controltower": NoLZClient(), "organizations": FakeClient(),
                            "sts": FakeClient({"get_caller_identity": {"Account": "1"}})})
        ctx = ct.Context(sess, "us-east-1", "AWSControlTowerExecution")
        rpt = ct.Report()
        ok = ctx.discover(rpt)
        self.assertFalse(ok)
        self.assertIn(ct.BLOCKER, levels(rpt))


if __name__ == "__main__":
    unittest.main(verbosity=2)

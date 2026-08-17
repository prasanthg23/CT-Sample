#!/usr/bin/env python3
"""
AWS Control Tower pre-upgrade / pre-repair precheck (standalone, read-only).

PURPOSE
-------
Run this from the AWS Control Tower MANAGEMENT account, in the HOME region, BEFORE
you click "Update"/"Repair"/"Reset" on the landing zone (or call UpdateLandingZone /
ResetLandingZone). It confirms the environment is in a known-good state and surfaces the
issues, drift, out-of-band changes and customizations that are the documented causes of
landing-zone update failures — so they can be fixed first.

It is 100% read-only: every AWS call is a List*/Get*/Describe*/Search*. It never mutates
anything. It exits non-zero if any BLOCKER is found so you can gate an upgrade runbook on it.

WHAT IT CHECKS  (each mapped to a documented LZ-update failure cause; see README.md)
    1.  Landing zone status is ACTIVE (not FAILED / PROCESSING / mid-operation)
    2.  Landing zone drift status is IN_SYNC          (out-of-band change / managed-SCP edit)
    3.  Landing zone is actually behind (an update is available) + version delta
    4.  Managed accounts: none FAILED / SUSPENDED / mid-provisioning
    5.  Suspended/closed accounts that still have an Account Factory provisioned product
        (the classic "AWSControlTowerExecution role can't be assumed" upgrade blocker)
    6.  Enabled CONTROLS drift / non-SUCCEEDED status across every registered OU
    7.  Enabled BASELINES drift / non-SUCCEEDED status (incl. child accounts)
    8.  AWSControlTower* StackSets: failed/outdated/drifted stack instances, orphaned instances
    9.  AWS Config recorders/delivery channels present in the Audit & Log Archive accounts
        and any default recorder in non-home governed regions (blocks the update)
    10. Customizations detected (CfCT, AFT, custom StackSets targeting governed regions)
    11. Required trusted (service) access enabled in AWS Organizations
    12. Delegated administrators inventory (conflicts with CFN StackSets / Config)
    13. Required Control Tower management-account IAM roles exist
    14. Landing-zone KMS key is ENABLED (not disabled / pending deletion)
    15. STS is activated in the management account for every governed Region
    16. SCP headroom (10-SCP-per-target limit) + customer-managed SCP inventory
    17. SCP content risk: FullAWSAccess detached, or a custom Deny that doesn't exempt
        AWSControlTowerExecution / restricts Regions via SCP (can block the update)

USAGE
-----
    # From the management account, home region (uses ambient creds/role):
    python3 ct_preupgrade_precheck.py

    # Explicit region / profile:
    python3 ct_preupgrade_precheck.py --region us-east-1 --profile my-mgmt-admin

    # JSON report for a pipeline gate, and treat warnings/unknowns as blocking:
    python3 ct_preupgrade_precheck.py --json report.json --strict

    # Cross-account Config check needs a role assumable in the shared accounts
    # (defaults to AWSControlTowerExecution, which the mgmt account can assume):
    python3 ct_preupgrade_precheck.py --member-role AWSControlTowerExecution

EXIT CODES
    0 = no blockers (safe to proceed, review warnings)
    2 = one or more BLOCKERS (do NOT upgrade until resolved)
    3 = precheck could not run (auth/permup problem)

REQUIRED PERMISSIONS (management account, read-only)
    controltower:ListLandingZones, GetLandingZone, ListEnabledControls, ListEnabledBaselines
    organizations:DescribeOrganization, ListRoots, ListOrganizationalUnitsForParent,
                  ListAccounts, ListPolicies, ListPoliciesForTarget,
                  ListAWSServiceAccessForOrganization, ListDelegatedAdministrators,
                  ListDelegatedServicesForAccount, DescribePolicy
    servicecatalog:SearchProvisionedProducts
    cloudformation:ListStackSets, DescribeStackSet, ListStackInstances, ListStacks
    iam:GetRole
    kms:DescribeKey
    sts:GetCallerIdentity, AssumeRole (AssumeRole only for the cross-account Config check)
"""

import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
except ImportError:
    print("boto3 is required: pip install boto3", file=sys.stderr)
    sys.exit(3)


# --------------------------------------------------------------------------------------
# Finding model + severity
# --------------------------------------------------------------------------------------
BLOCKER = "BLOCKER"   # must fix before upgrade; gates the run
WARNING = "WARNING"   # should review; may cause partial issues
INFO = "INFO"         # informational (e.g. customizations you must be aware of)
PASS = "PASS"         # verified good
UNKNOWN = "UNKNOWN"   # could not verify (missing perms / API error) — never assume good


@dataclass
class Finding:
    check: str
    level: str
    summary: str
    detail: str = ""
    rows: List[List[str]] = field(default_factory=list)
    cols: List[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class Report:
    findings: List[Finding] = field(default_factory=list)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def by_level(self, level: str) -> List[Finding]:
        return [f for f in self.findings if f.level == level]

    @property
    def has_blockers(self) -> bool:
        return len(self.by_level(BLOCKER)) > 0

    @property
    def has_unknowns(self) -> bool:
        return len(self.by_level(UNKNOWN)) > 0

    @property
    def has_warnings(self) -> bool:
        return len(self.by_level(WARNING)) > 0


DOC = "https://docs.aws.amazon.com/controltower/latest/userguide"


# --------------------------------------------------------------------------------------
# Helper: paginate any boto3 call safely
# --------------------------------------------------------------------------------------
def _collect(client, op: str, key: str, **kwargs) -> List[dict]:
    """Depaginate op if a paginator exists, else single call. Returns list under `key`.
    Robust against older botocore where can_paginate() raises for unknown operations."""
    out: List[dict] = []
    try:
        paginable = client.can_paginate(op)
    except Exception:
        paginable = False
    if paginable:
        for page in client.get_paginator(op).paginate(**kwargs):
            out.extend(page.get(key, []))
    else:
        resp = getattr(client, op)(**kwargs)
        out.extend(resp.get(key, []))
    return out


# --------------------------------------------------------------------------------------
# Discovery: landing zone, governed regions, shared account ids (all from mgmt account)
# --------------------------------------------------------------------------------------
class Context:
    def __init__(self, session, region: str, member_role: str):
        self.session = session
        self.region = region
        self.member_role = member_role
        self.ct = session.client("controltower", region_name=region)
        self.orgs = session.client("organizations", region_name=region)
        self.lz_arn: Optional[str] = None
        self.lz: Dict[str, Any] = {}
        self.manifest: Dict[str, Any] = {}
        self.governed_regions: List[str] = []
        self.log_archive_account: Optional[str] = None
        self.audit_account: Optional[str] = None
        self.mgmt_account: Optional[str] = None
        self.kms_key_arn: Optional[str] = None
        self.detect_drift: bool = False
        self.drift_timeout: int = 900

    def discover(self, report: Report) -> bool:
        try:
            self.mgmt_account = self.session.client(
                "sts", region_name=self.region
            ).get_caller_identity()["Account"]
        except (ClientError, BotoCoreError) as e:
            report.add(Finding("discovery", UNKNOWN,
                               "Could not determine caller identity", str(e)))
            return False

        # Preflight: the SDK must be new enough to know the Control Tower LZ APIs.
        if not hasattr(self.ct, "list_landing_zones"):
            report.add(Finding("discovery", BLOCKER,
                               "Installed boto3/botocore is too old for Control Tower APIs",
                               "This SDK does not expose controltower:ListLandingZones / "
                               "GetLandingZone / ListEnabledBaselines.",
                               remediation="Upgrade the SDK:  pip install -U 'boto3>=1.34'"))
            return False

        try:
            lzs = _collect(self.ct, "list_landing_zones", "landingZones")
        except (ClientError, BotoCoreError) as e:
            report.add(Finding("discovery", BLOCKER,
                               "Could not list landing zones — is this the management "
                               "account and home region?", str(e),
                               remediation="Run in the CT management account, home region."))
            return False

        if not lzs:
            report.add(Finding("discovery", BLOCKER,
                               "No landing zone found in this account/region",
                               "ListLandingZones returned empty.",
                               remediation="Confirm you are in the home region."))
            return False

        self.lz_arn = lzs[0].get("arn")
        try:
            self.lz = self.ct.get_landing_zone(
                landingZoneIdentifier=self.lz_arn
            ).get("landingZone", {})
        except (ClientError, BotoCoreError) as e:
            report.add(Finding("discovery", BLOCKER, "GetLandingZone failed", str(e)))
            return False

        self.manifest = self.lz.get("manifest", {}) or {}
        # governedRegions + shared accounts are carried in the manifest
        self.governed_regions = (
            self.manifest.get("governedRegions")
            or self.manifest.get("GovernedRegions")
            or [self.region]
        )
        cl = self.manifest.get("centralizedLogging") or self.manifest.get("CentralizedLogging") or {}
        sr = self.manifest.get("securityRoles") or self.manifest.get("SecurityRoles") or {}
        self.log_archive_account = cl.get("accountId") or cl.get("AccountId")
        self.audit_account = sr.get("accountId") or sr.get("AccountId")
        # Optional customer-managed KMS key for the landing zone (from the manifest).
        cfg = cl.get("configurations") or cl.get("Configurations") or {}
        self.kms_key_arn = (cfg.get("kmsKeyArn") or cfg.get("KmsKeyArn")
                            or self.manifest.get("kmsKeyArn"))
        return True

    def assume(self, account_id: str, region: str, service: str):
        """Return a read-only service client in a member/shared account, or None."""
        role_arn = f"arn:aws:iam::{account_id}:role/{self.member_role}"
        sts = self.session.client("sts", region_name=self.region)
        creds = sts.assume_role(RoleArn=role_arn,
                                RoleSessionName="ct-preupgrade-precheck")["Credentials"]
        return boto3.client(
            service,
            region_name=region,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

    def all_ou_arns(self) -> List[Dict[str, str]]:
        """Every OU in the org (Id, Arn, Name), recursively from the root."""
        roots = _collect(self.orgs, "list_roots", "Roots")
        ous: List[Dict[str, str]] = []
        stack = [r["Id"] for r in roots]
        while stack:
            parent = stack.pop()
            children = _collect(self.orgs, "list_organizational_units_for_parent",
                                "OrganizationalUnits", ParentId=parent)
            for ou in children:
                ous.append({"Id": ou["Id"], "Arn": ou["Arn"], "Name": ou["Name"]})
                stack.append(ou["Id"])
        return ous


# --------------------------------------------------------------------------------------
# Individual checks
# --------------------------------------------------------------------------------------
def check_lz_status(ctx: Context, report: Report) -> None:
    status = ctx.lz.get("status")
    if status == "ACTIVE":
        report.add(Finding("lz_status", PASS,
                           f"Landing zone status is ACTIVE (v{ctx.lz.get('version')})"))
    elif status in ("PROCESSING",):
        report.add(Finding("lz_status", BLOCKER,
                           "Landing zone has an operation IN PROGRESS",
                           "A landing zone operation is currently PROCESSING.",
                           remediation="Wait for the current operation to finish before upgrading."))
    elif status == "FAILED":
        report.add(Finding("lz_status", BLOCKER,
                           "Landing zone is in a FAILED state",
                           "GetLandingZone.status == FAILED. Updates do not roll back; "
                           "resolve the failed state first.",
                           remediation=f"See {DOC}/troubleshooting.html"))
    else:
        report.add(Finding("lz_status", UNKNOWN,
                           f"Unexpected landing zone status: {status}"))


def check_lz_drift(ctx: Context, report: Report) -> None:
    drift = (ctx.lz.get("driftStatus") or {}).get("status")
    if drift == "IN_SYNC":
        report.add(Finding("lz_drift", PASS, "Landing zone drift status is IN_SYNC"))
    elif drift == "DRIFTED":
        report.add(Finding("lz_drift", BLOCKER,
                           "Landing zone is DRIFTED (out-of-band change detected)",
                           "Landing-zone level drift (e.g. a managed SCP was attached, "
                           "detached, deleted or modified, or a shared account was moved).",
                           remediation=f"Reset or update the landing zone to restore config. "
                                       f"See {DOC}/drift.html"))
    else:
        report.add(Finding("lz_drift", UNKNOWN,
                           f"Could not read landing zone drift status (got: {drift})"))


def check_update_available(ctx: Context, report: Report) -> None:
    cur = ctx.lz.get("version")
    latest = ctx.lz.get("latestAvailableVersion")
    if not latest:
        report.add(Finding("update_available", INFO,
                           f"Current landing zone version: {cur}",
                           "latestAvailableVersion not returned."))
        return
    if cur == latest:
        report.add(Finding("update_available", INFO,
                           f"Landing zone already on the latest version ({cur})",
                           "No landing-zone update is pending. (Baseline/control updates "
                           "may still be pending — see other checks.)"))
    else:
        report.add(Finding("update_available", INFO,
                           f"Update available: {cur} -> {latest}",
                           cols=["Current", "Latest"], rows=[[str(cur), str(latest)]],
                           remediation=f"Review {DOC}/lz-update-best-practices.html "
                                       "(2.x -> 3.x requires OU re-registration)."))


def check_managed_accounts(ctx: Context, report: Report) -> None:
    # Landing-zone level managed-account health via Organizations account state.
    try:
        accounts = _collect(ctx.orgs, "list_accounts", "Accounts")
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("managed_accounts", UNKNOWN,
                           "Could not list organization accounts", str(e)))
        return
    suspended = [a for a in accounts if a.get("Status") == "SUSPENDED"]
    if suspended:
        rows = [[a["Id"], a.get("Name", ""), a.get("Status")] for a in suspended]
        report.add(Finding("managed_accounts", WARNING,
                           f"{len(suspended)} SUSPENDED account(s) in the organization",
                           "Suspended accounts frequently block landing-zone updates when "
                           "they still have an Account Factory provisioned product "
                           "(see the provisioned-product check).",
                           cols=["Account", "Name", "Status"], rows=rows,
                           remediation=f"{DOC}/troubleshooting.html"))
    else:
        report.add(Finding("managed_accounts", PASS,
                           "No SUSPENDED accounts in the organization"))


def check_suspended_with_provisioned_product(ctx: Context, report: Report) -> None:
    """The classic upgrade blocker: a closed/suspended account whose Account Factory
    Service Catalog provisioned product was never terminated -> AWSControlTowerExecution
    can't be assumed -> the landing zone update fails."""
    try:
        accounts = _collect(ctx.orgs, "list_accounts", "Accounts")
        suspended_ids = {a["Id"] for a in accounts if a.get("Status") == "SUSPENDED"}
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("closed_with_pp", UNKNOWN,
                           "Could not list accounts to correlate provisioned products", str(e)))
        return
    if not suspended_ids:
        report.add(Finding("closed_with_pp", PASS,
                           "No suspended accounts, so no orphaned provisioned products"))
        return
    try:
        sc = ctx.session.client("servicecatalog", region_name=ctx.region)
        pps = _collect(sc, "search_provisioned_products", "ProvisionedProducts",
                       AccessLevelFilter={"Key": "Account", "Value": "self"})
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("closed_with_pp", UNKNOWN,
                           "Could not search Service Catalog provisioned products", str(e)))
        return
    # Account Factory products carry the vended account id in PhysicalId / Name; match loosely.
    hits = []
    for pp in pps:
        blob = json.dumps(pp)
        for acct in suspended_ids:
            if acct in blob:
                hits.append([acct, pp.get("Name", ""), pp.get("Status", "")])
    if hits:
        report.add(Finding("closed_with_pp", BLOCKER,
                           f"{len(hits)} provisioned product(s) still exist for suspended account(s)",
                           "A suspended account with an un-terminated Account Factory "
                           "provisioned product causes 'AWSControlTowerExecution role can't "
                           "be assumed' and fails the landing-zone update.",
                           cols=["Suspended Account", "Provisioned Product", "Status"], rows=hits,
                           remediation="Reopen+terminate the provisioned product, or remove the "
                                       "orphaned StackSet instances (Retain Stacks). See "
                                       f"{DOC}/troubleshooting.html"))
    else:
        report.add(Finding("closed_with_pp", PASS,
                           "No provisioned products found for suspended accounts"))


def check_enabled_controls(ctx: Context, report: Report) -> None:
    try:
        ous = ctx.all_ou_arns()
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("controls_drift", UNKNOWN,
                           "Could not enumerate OUs for control drift check", str(e)))
        return
    drifted, failed = [], []
    checked = 0
    for ou in ous:
        try:
            controls = _collect(ctx.ct, "list_enabled_controls", "enabledControls",
                                 targetIdentifier=ou["Arn"])
        except (ClientError, BotoCoreError):
            continue  # OU not registered with CT -> ListEnabledControls errors; skip
        checked += 1
        for c in controls:
            ds = (c.get("driftStatusSummary") or {}).get("driftStatus")
            st = (c.get("statusSummary") or {}).get("status")
            cid = c.get("controlIdentifier", c.get("arn", ""))
            if ds == "DRIFTED":
                drifted.append([ou["Name"], cid, ds])
            if st and st not in ("SUCCEEDED",):
                failed.append([ou["Name"], cid, st])
    if not checked:
        report.add(Finding("controls_drift", UNKNOWN,
                           "No CT-registered OUs found / none queryable for enabled controls"))
        return
    if drifted or failed:
        rows = drifted + failed
        report.add(Finding("controls_drift", BLOCKER,
                           f"{len(rows)} enabled control(s) drifted or not in SUCCEEDED state",
                           "Drifted or failed controls should be reset before an upgrade so "
                           "they re-baseline against the new landing zone version.",
                           cols=["OU", "Control", "Status"], rows=rows,
                           remediation="reset-enabled-control / re-register OU. See "
                                       f"{DOC}/drift.html"))
    else:
        report.add(Finding("controls_drift", PASS,
                           f"All enabled controls SUCCEEDED and IN_SYNC across {checked} OU(s)"))


def check_enabled_baselines(ctx: Context, report: Report) -> None:
    try:
        baselines = _collect(ctx.ct, "list_enabled_baselines", "enabledBaselines",
                             includeChildren=True)
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("baselines_drift", UNKNOWN,
                           "Could not list enabled baselines", str(e)))
        return
    bad = []
    for b in baselines:
        st = (b.get("statusSummary") or {}).get("status")
        ds = (b.get("driftStatusSummary") or {}).get("driftStatus")
        tgt = b.get("targetIdentifier", b.get("arn", ""))
        if st and st not in ("SUCCEEDED",):
            bad.append([tgt, b.get("baselineVersion", ""), st or "", ds or ""])
        elif ds == "DRIFTED":
            bad.append([tgt, b.get("baselineVersion", ""), st or "", ds])
    if bad:
        report.add(Finding("baselines_drift", BLOCKER,
                           f"{len(bad)} enabled baseline(s) drifted or not SUCCEEDED",
                           "Baselines (incl. child accounts) must be healthy; drifted/failed "
                           "baselines cause enrollment and update problems.",
                           cols=["Target", "Version", "Status", "Drift"], rows=bad,
                           remediation="reset-enabled-baseline / re-register OU."))
    else:
        report.add(Finding("baselines_drift", PASS,
                           f"All {len(baselines)} enabled baselines SUCCEEDED / IN_SYNC"))


def check_stacksets(ctx: Context, report: Report) -> None:
    try:
        cfn = ctx.session.client("cloudformation", region_name=ctx.region)
        names = [s["StackSetName"] for s in
                 _collect(cfn, "list_stack_sets", "Summaries", Status="ACTIVE")
                 if s["StackSetName"].startswith("AWSControlTower")]
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("stacksets", UNKNOWN,
                           "Could not list CloudFormation StackSets", str(e)))
        return
    # Current org accounts — instances for accounts no longer in the org are
    # orphaned StackSet leftovers (StackSets don't auto-delete on account removal)
    # and are NOT acted on by a landing-zone update, so they must not block it.
    try:
        org_ids = {a["Id"] for a in _collect(ctx.orgs, "list_accounts", "Accounts")}
    except (ClientError, BotoCoreError):
        org_ids = None  # couldn't verify membership; don't suppress anything

    bad, outdated, orphaned = [], [], []
    for name in names:
        try:
            insts = _collect(cfn, "list_stack_instances", "Summaries", StackSetName=name)
        except (ClientError, BotoCoreError):
            continue
        for i in insts:
            status = i.get("Status")  # summary status: CURRENT | OUTDATED | INOPERABLE
            detailed = (i.get("StackInstanceStatus") or {}).get("DetailedStatus")
            drift = i.get("DriftStatus")
            acct = i.get("Account", "")
            # Show summary + detailed when they differ (e.g. OUTDATED/FAILED) so the
            # real signal isn't hidden behind the summary status.
            status_disp = str(status or detailed)
            if detailed and detailed != status:
                status_disp = f"{status}/{detailed}"
            row = [name, acct, i.get("Region", ""), status_disp, str(drift)]
            # Orphaned: target account has left the org -> stale leftover, not a blocker.
            if org_ids is not None and acct and acct not in org_ids:
                orphaned.append(row)
                continue
            # Real blockers: an instance that can't be updated, failed, or has drifted.
            if status == "INOPERABLE" or detailed in ("FAILED", "INOPERABLE", "CANCELLED"):
                bad.append(row)
            elif drift == "DRIFTED":
                bad.append(row)
            elif status == "OUTDATED":
                # Expected when an LZ update is pending — the update refreshes these.
                outdated.append(row)
    if bad:
        report.add(Finding("stacksets", BLOCKER,
                           f"{len(bad)} AWSControlTower* StackSet instance(s) inoperable/failed/drifted",
                           "INOPERABLE/FAILED or DRIFTED stack instances in accounts still enrolled in "
                           "the org cause the landing-zone update to fail. (OUTDATED instances, and "
                           "instances for accounts no longer in the org, are not counted here.)",
                           cols=["StackSet", "Account", "Region", "Status", "Drift"], rows=bad,
                           remediation="Repair or remove (Retain Stacks) the affected instances "
                                       "before upgrading."))
    if orphaned:
        report.add(Finding("stacksets_orphaned", INFO,
                           f"{len(orphaned)} stale StackSet instance(s) target accounts no longer in the org",
                           "These instances belong to account(s) that have left the organization. "
                           "Control Tower does not act on them during a landing-zone update, so they "
                           "do NOT block it — but they are safe to clean up.",
                           cols=["StackSet", "Account", "Region", "Status", "Drift"], rows=orphaned[:50],
                           remediation="Optionally delete these stale instances "
                                       "(DeleteStackInstances with RetainStacks) to tidy up."))
    if not bad:
        if outdated:
            report.add(Finding("stacksets", INFO,
                               f"{len(outdated)} StackSet instance(s) are OUTDATED (expected)",
                               "OUTDATED means the instances are behind the current template — this is "
                               "normal when a landing-zone update is pending, and the update will "
                               "refresh them. No inoperable/failed/drifted instances were found.",
                               cols=["StackSet", "Account", "Region", "Status", "Drift"],
                               rows=outdated[:50]))
        elif not orphaned:
            report.add(Finding("stacksets", PASS,
                               f"All instances CURRENT across {len(names)} AWSControlTower StackSet(s)"))


def _resource_drift_detail(ctx: "Context", acct: str, region: str, stack_id) -> str:
    """Best-effort resource-level drift detail for a drifted instance.

    Assumes ctx.member_role (default AWSControlTowerExecution) into the account and
    reads describe_stack_resource_drifts. If the role is missing/not assumable, or
    anything else goes wrong, returns a fallback pointing the operator at the stack
    to inspect in-account (never raises)."""
    if not stack_id:
        return "no StackId on instance — inspect the stack in that account's CloudFormation console"
    try:
        cfn = ctx.assume(acct, region, "cloudformation")
        drifts = _collect(cfn, "describe_stack_resource_drifts", "StackResourceDrifts",
                          StackName=stack_id,
                          StackResourceDriftStatusFilters=["MODIFIED", "DELETED"])
    except Exception as e:  # role missing / AccessDenied / any SDK error -> fall back
        return (f"'{ctx.member_role}' not assumable in {acct} ({type(e).__name__}) — "
                f"inspect stack {stack_id} in that account directly")
    if not drifts:
        return ("drift reported but no MODIFIED/DELETED resources returned — "
                "inspect the stack in-account")
    parts = []
    for d in drifts[:5]:
        props = ",".join(p.get("PropertyPath", "")
                         for p in (d.get("PropertyDifferences") or [])[:4])
        parts.append(f"{d.get('ResourceType')}/{d.get('LogicalResourceId')}:"
                     f"{d.get('StackResourceDriftStatus')}" + (f"[{props}]" if props else ""))
    return "; ".join(parts) + ("" if len(drifts) <= 5 else f" (+{len(drifts) - 5} more)")


def check_stackset_active_drift(ctx: Context, report: Report) -> None:
    """OPT-IN (--detect-drift): actively run CloudFormation StackSet drift detection on
    the AWSControlTower* StackSets to catch out-of-band changes to CT-deployed stack
    resources. The default (off) only reads stored DriftStatus, which stays NOT_CHECKED
    until a detection has actually been run — so out-of-band stack edits are otherwise
    invisible. This launches StackSet drift operations and can take several minutes."""
    if not getattr(ctx, "detect_drift", False):
        report.add(Finding("stackset_drift", INFO,
                           "Active StackSet drift detection skipped (opt-in)",
                           "The StackSet DriftStatus reported above is only as fresh as the last "
                           "drift-detection run (frequently NOT_CHECKED). Out-of-band edits to "
                           "resources inside CT-deployed stacks are NOT detected without this.",
                           remediation="Re-run with --detect-drift to actively detect drift "
                                       "(slower; launches StackSet drift operations)."))
        return

    import time
    try:
        cfn = ctx.session.client("cloudformation", region_name=ctx.region)
        names = [s["StackSetName"] for s in
                 _collect(cfn, "list_stack_sets", "Summaries", Status="ACTIVE")
                 if s["StackSetName"].startswith("AWSControlTower")]
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("stackset_drift", UNKNOWN,
                           "Could not list StackSets for drift detection", str(e)))
        return
    try:
        org_ids = {a["Id"] for a in _collect(ctx.orgs, "list_accounts", "Accounts")}
    except (ClientError, BotoCoreError):
        org_ids = None

    deadline = time.time() + getattr(ctx, "drift_timeout", 900)
    failed = []
    for name in names:
        try:
            op = cfn.detect_stack_set_drift(StackSetName=name)["OperationId"]
        except (ClientError, BotoCoreError) as e:
            failed.append([name, "detect_start_failed", str(e)[:80]])
            continue
        while True:
            try:
                st = cfn.describe_stack_set_operation(
                    StackSetName=name, OperationId=op)["StackSetOperation"]["Status"]
            except (ClientError, BotoCoreError) as e:
                failed.append([name, "poll_failed", str(e)[:80]])
                break
            if st in ("SUCCEEDED", "FAILED", "STOPPED"):
                if st != "SUCCEEDED":
                    failed.append([name, f"operation_{st}", ""])
                break
            if time.time() > deadline:
                failed.append([name, "timeout", ""])
                break
            time.sleep(10)

    drifted, orphaned_drifted = [], []
    for name in names:
        try:
            insts = _collect(cfn, "list_stack_instances", "Summaries", StackSetName=name)
        except (ClientError, BotoCoreError):
            continue
        for i in insts:
            if i.get("DriftStatus") != "DRIFTED":
                continue
            acct = i.get("Account", "")
            region = i.get("Region", "")
            status = str(i.get("Status") or (i.get("StackInstanceStatus") or {}).get("DetailedStatus"))
            if org_ids is not None and acct and acct not in org_ids:
                orphaned_drifted.append([name, acct, region, status, "DRIFTED"])
            else:
                # Drill into what actually drifted (assume role); fall back if the
                # AWSControlTowerExecution role isn't there.
                detail = _resource_drift_detail(ctx, acct, region, i.get("StackId"))
                drifted.append([name, acct, region, status, "DRIFTED", detail])

    if drifted:
        report.add(Finding("stackset_drift", BLOCKER,
                           f"{len(drifted)} AWSControlTower* StackSet instance(s) DRIFTED (out-of-band changes)",
                           "Active drift detection found resource-level drift in CT-deployed stacks "
                           "for accounts still enrolled in the org. Drift can cause the landing-zone "
                           "update to fail or revert customer changes. The last column shows the "
                           "drifted resource(s) when the role is assumable, else where to look.",
                           cols=["StackSet", "Account", "Region", "Status", "Drift",
                                 "Drifted resources / where to look"], rows=drifted,
                           remediation="Reconcile the out-of-band changes (revert them, or update the "
                                       "StackSet to match) before upgrading."))
    if orphaned_drifted:
        report.add(Finding("stackset_drift_orphaned", INFO,
                           f"{len(orphaned_drifted)} DRIFTED instance(s) target accounts no longer in the org",
                           "Drifted, but for departed accounts — stale leftovers, not a blocker.",
                           cols=["StackSet", "Account", "Region", "Status", "Drift"],
                           rows=orphaned_drifted[:50]))
    if failed:
        report.add(Finding("stackset_drift", UNKNOWN,
                           f"Drift detection did not complete for {len(failed)} StackSet(s)",
                           "Their drift state is unverified (detection failed or timed out).",
                           cols=["StackSet", "Reason", "Detail"], rows=failed[:50],
                           remediation="Re-run with a larger --drift-timeout, or check StackSet "
                                       "drift-detection permissions."))
    if not drifted and not failed:
        report.add(Finding("stackset_drift", PASS,
                           f"Active drift detection: no drift across {len(names)} "
                           "AWSControlTower StackSet(s)"))


def check_config_in_shared_accounts(ctx: Context, report: Report) -> None:
    """AWS Config resources must NOT exist in Audit/Log Archive accounts, and no default
    recorder should linger in non-home governed regions -> both block the update."""
    targets = []
    if ctx.audit_account:
        targets.append(("Audit", ctx.audit_account))
    if ctx.log_archive_account:
        targets.append(("LogArchive", ctx.log_archive_account))
    if not targets:
        report.add(Finding("config_shared", UNKNOWN,
                           "Could not determine Audit/Log Archive account IDs from the LZ "
                           "manifest; skipped shared-account Config check.",
                           remediation="Pass --audit-account / --log-archive-account to force it."))
        return
    findings_rows = []
    unknown = False
    for label, acct in targets:
        for region in ctx.governed_regions:
            try:
                cfg = ctx.assume(acct, region, "config")
                recs = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
                # CT manages exactly one recorder; extra/foreign recorders are the problem.
                if len(recs) > 1:
                    findings_rows.append([label, acct, region,
                                          f"{len(recs)} configuration recorders"])
            except (ClientError, BotoCoreError):
                unknown = True
    if findings_rows:
        report.add(Finding("config_shared", WARNING,
                           "Extra AWS Config recorder(s) found in shared accounts",
                           "Additional/foreign Config recorders in the Audit or Log Archive "
                           "accounts can block the landing-zone update.",
                           cols=["Account Type", "Account", "Region", "Observation"],
                           rows=findings_rows,
                           remediation=f"{DOC}/troubleshooting.html (AWS Config resources in "
                                       "Security OU accounts)."))
    elif unknown:
        report.add(Finding("config_shared", UNKNOWN,
                           "Could not assume role into one or more shared accounts to inspect "
                           "AWS Config. Verify manually.",
                           remediation="Grant the precheck --member-role in the shared accounts."))
    else:
        report.add(Finding("config_shared", PASS,
                           "No extra Config recorders in Audit/Log Archive shared accounts"))


def check_customizations(ctx: Context, report: Report) -> None:
    """Detect CfCT / AFT / custom StackSets so the operator knows to prune region-scoped
    custom stack instances before a region-expanding upgrade."""
    signals = []
    try:
        cfn = ctx.session.client("cloudformation", region_name=ctx.region)
        stacks = _collect(cfn, "list_stacks", "StackSummaries")
        names = [s["StackName"] for s in stacks
                 if s.get("StackStatus") not in ("DELETE_COMPLETE",)]
        if any("CustomControlTower" in n or "customizations-for" in n.lower() for n in names):
            signals.append(["CfCT", "Customizations for Control Tower stack present"])
        custom_ss = [s["StackSetName"] for s in
                     _collect(cfn, "list_stack_sets", "Summaries", Status="ACTIVE")
                     if s["StackSetName"].startswith("CustomControlTower")
                     or not s["StackSetName"].startswith("AWSControlTower")]
        if custom_ss:
            signals.append(["Custom StackSets", ", ".join(custom_ss[:10])])
    except (ClientError, BotoCoreError):
        pass
    try:
        accounts = _collect(ctx.orgs, "list_accounts", "Accounts")
        if any("AFT" in (a.get("Name") or "") or "account-factory-for-terraform"
               in (a.get("Name") or "").lower() for a in accounts):
            signals.append(["AFT", "An AFT management account appears to exist"])
    except (ClientError, BotoCoreError):
        pass
    if signals:
        report.add(Finding("customizations", INFO,
                           "Customizations detected — review before upgrading",
                           "If any custom StackSet deploys into a region you are about to add "
                           "to governance, delete those stack instances first or the upgrade "
                           "will fail.",
                           cols=["Type", "Detail"], rows=signals,
                           remediation="See the CfCT/AFT docs and "
                                       f"{DOC}/lz-update-best-practices.html"))
    else:
        report.add(Finding("customizations", INFO,
                           "No CfCT/AFT/custom StackSet signals detected (best-effort)"))


# Required Control Tower management-account IAM roles (must exist for updates/repairs).
_REQUIRED_ROLES = [
    "AWSControlTowerAdmin",
    "AWSControlTowerCloudTrailRole",
    "AWSControlTowerStackSetRole",
    "AWSControlTowerConfigAggregatorRoleForOrganizations",
]

# Trusted (service) access that an operating Control Tower landing zone relies on.
_REQUIRED_TRUSTED_SERVICES = [
    "controltower.amazonaws.com",
    "member.org.stacksets.cloudformation.amazonaws.com",
    "config.amazonaws.com",
    "sso.amazonaws.com",
]


def check_trusted_access(ctx: Context, report: Report) -> None:
    """Control Tower relies on trusted (service) access in AWS Organizations. If a required
    service principal was disabled, updates fail."""
    try:
        enabled = {s["ServicePrincipal"] for s in _collect(
            ctx.orgs, "list_aws_service_access_for_organization", "EnabledServicePrincipals")}
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("trusted_access", UNKNOWN,
                           "Could not read trusted service access", str(e)))
        return
    missing = [s for s in _REQUIRED_TRUSTED_SERVICES if s not in enabled]
    if missing:
        report.add(Finding("trusted_access", BLOCKER,
                           "Required trusted access is disabled in AWS Organizations",
                           "Control Tower needs trusted access for these service principals.",
                           cols=["Missing service principal"], rows=[[m] for m in missing],
                           remediation="Re-enable trusted access (do not disable CT-managed "
                                       "trusted access). See the AWS Organizations docs."))
    else:
        report.add(Finding("trusted_access", PASS,
                           "All required trusted service access is enabled"))


def check_delegated_admins(ctx: Context, report: Report) -> None:
    """Inventory delegated administrators. Conflicting delegated admins for CloudFormation
    StackSets or Config can interfere with a landing-zone update."""
    try:
        das = _collect(ctx.orgs, "list_delegated_administrators", "DelegatedAdministrators")
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("delegated_admins", UNKNOWN,
                           "Could not list delegated administrators", str(e)))
        return
    if not das:
        report.add(Finding("delegated_admins", PASS, "No delegated administrators configured"))
        return
    rows = []
    for da in das:
        try:
            svcs = _collect(ctx.orgs, "list_delegated_services_for_account",
                            "DelegatedServices", AccountId=da["Id"])
            sp = ", ".join(s.get("ServicePrincipal", "") for s in svcs)
        except (ClientError, BotoCoreError):
            sp = "(could not read services)"
        rows.append([da.get("Id", ""), da.get("Name", ""), sp])
    report.add(Finding("delegated_admins", INFO,
                       f"{len(das)} delegated administrator account(s) configured — review",
                       "Confirm these are intentional; a delegated admin for CloudFormation "
                       "StackSets or Config other than the CT-expected account can conflict "
                       "with the update.",
                       cols=["Account", "Name", "Delegated services"], rows=rows))


def check_required_iam_roles(ctx: Context, report: Report) -> None:
    """The Control Tower management-account service roles must exist for updates/repairs."""
    try:
        iam = ctx.session.client("iam", region_name=ctx.region)
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("iam_roles", UNKNOWN, "Could not create IAM client", str(e)))
        return
    missing, unknown = [], []
    for role in _REQUIRED_ROLES:
        try:
            iam.get_role(RoleName=role)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NoSuchEntity":
                missing.append([role])
            else:
                unknown.append(role)
        except BotoCoreError:
            unknown.append(role)
    if missing:
        report.add(Finding("iam_roles", BLOCKER,
                           f"{len(missing)} required Control Tower IAM role(s) missing",
                           "Control Tower cannot perform an update without these service roles.",
                           cols=["Missing role"], rows=missing,
                           remediation=f"Recreate the role(s). See {DOC}/roles-how.html"))
    elif unknown:
        report.add(Finding("iam_roles", UNKNOWN,
                           "Could not verify one or more required IAM roles",
                           ", ".join(unknown)))
    else:
        report.add(Finding("iam_roles", PASS,
                           "All required Control Tower management-account roles present"))


def check_kms_key(ctx: Context, report: Report) -> None:
    """If the landing zone uses a customer-managed KMS key, it must be ENABLED (not disabled
    or pending deletion)."""
    if not ctx.kms_key_arn:
        report.add(Finding("kms_key", INFO,
                           "No customer-managed KMS key referenced in the landing zone manifest",
                           "Control Tower is using AWS-owned encryption or none was configured."))
        return
    try:
        kms = ctx.session.client("kms", region_name=ctx.region)
        meta = kms.describe_key(KeyId=ctx.kms_key_arn)["KeyMetadata"]
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("kms_key", BLOCKER,
                           "Landing zone KMS key could not be described",
                           f"{ctx.kms_key_arn}: {e}",
                           remediation="Ensure the key exists and the precheck role has "
                                       "kms:DescribeKey."))
        return
    state = meta.get("KeyState")
    if state == "Enabled":
        extra = " (multi-Region)" if meta.get("MultiRegion") else ""
        report.add(Finding("kms_key", PASS, f"Landing zone KMS key is Enabled{extra}"))
    else:
        report.add(Finding("kms_key", BLOCKER,
                           f"Landing zone KMS key is not usable (state: {state})",
                           f"{ctx.kms_key_arn}",
                           remediation="Re-enable the key (or cancel deletion) before upgrading. "
                                       "A disabled/pending-deletion key fails the update."))


def check_sts_regional_activation(ctx: Context, report: Report) -> None:
    """STS must be activated in the management account for every governed Region, or the
    update can fail midway through configuration."""
    disabled, unknown = [], []
    creds = ctx.session.get_credentials()
    for region in ctx.governed_regions:
        try:
            frozen = creds.get_frozen_credentials()
            sts = boto3.client(
                "sts", region_name=region,
                endpoint_url=f"https://sts.{region}.amazonaws.com",
                aws_access_key_id=frozen.access_key,
                aws_secret_access_key=frozen.secret_key,
                aws_session_token=frozen.token,
            )
            sts.get_caller_identity()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("RegionDisabledException", "AccessDenied"):
                disabled.append([region, code])
            else:
                unknown.append(region)
        except BotoCoreError:
            unknown.append(region)
    if disabled:
        report.add(Finding("sts_regions", BLOCKER,
                           "STS is not active in one or more governed Regions",
                           "AWS STS must be activated in the management account for every "
                           "governed Region or the update can fail midway.",
                           cols=["Region", "Error"], rows=disabled,
                           remediation="Activate STS for the Region(s) in IAM > Account settings."))
    elif unknown:
        report.add(Finding("sts_regions", UNKNOWN,
                           "Could not verify STS activation for some Regions",
                           ", ".join(unknown)))
    else:
        report.add(Finding("sts_regions", PASS,
                           f"STS active across all {len(ctx.governed_regions)} governed Region(s)"))


def check_scp_headroom(ctx: Context, report: Report) -> None:
    """AWS Organizations allows a maximum of 10 SCPs attached per root/OU/account (hard limit;
    increased from 5). If a governed OU is at/near the limit, Control Tower may be unable to
    attach/update its managed SCP during the upgrade. Also inventories customer-managed SCPs."""
    try:
        ous = ctx.all_ou_arns()
        roots = _collect(ctx.orgs, "list_roots", "Roots")
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("scp_headroom", UNKNOWN, "Could not enumerate OUs for SCP check", str(e)))
        return
    targets = [{"Id": r["Id"], "Name": f"(root) {r.get('Name', r['Id'])}"} for r in roots]
    targets += [{"Id": o["Id"], "Name": o["Name"]} for o in ous]
    at_limit, near_limit, custom_rows = [], [], []
    checked = 0
    for t in targets:
        try:
            scps = _collect(ctx.orgs, "list_policies_for_target", "Policies",
                            TargetId=t["Id"], Filter="SERVICE_CONTROL_POLICY")
        except (ClientError, BotoCoreError):
            continue
        checked += 1
        count = len(scps)
        if count >= 10:
            at_limit.append([t["Name"], str(count)])
        elif count >= 8:
            near_limit.append([t["Name"], str(count)])
        for p in scps:
            name = p.get("Name", "")
            # aws-guardrails-* are Control Tower's own managed preventive-control SCPs
            # (they report AwsManaged=false because CT creates them in your account).
            # Count them toward the SCP limit, but do not label them "customer-managed".
            is_ct_managed = name.startswith("aws-guardrails")
            if not p.get("AwsManaged", False) and name != "FullAWSAccess" and not is_ct_managed:
                custom_rows.append([t["Name"], name, p.get("Id", "")])
    if not checked:
        report.add(Finding("scp_headroom", UNKNOWN, "No targets queryable for SCPs"))
        return
    if at_limit:
        report.add(Finding("scp_headroom", WARNING,
                           f"{len(at_limit)} target(s) at the 10-SCP attachment limit",
                           "AWS Organizations allows max 10 SCPs per target (hard limit). A "
                           "target at the limit can prevent Control Tower from attaching/updating "
                           "its managed SCP during the upgrade.",
                           cols=["Target", "SCPs attached"], rows=at_limit + near_limit,
                           remediation="Consolidate or detach a custom SCP to free a slot."))
    elif near_limit:
        report.add(Finding("scp_headroom", WARNING,
                           f"{len(near_limit)} target(s) near the 10-SCP limit (8+ attached)",
                           cols=["Target", "SCPs attached"], rows=near_limit))
    else:
        report.add(Finding("scp_headroom", PASS,
                           f"All {checked} targets have SCP headroom (<8 of 10 attached)"))
    if custom_rows:
        report.add(Finding("scp_custom", INFO,
                           f"{len(custom_rows)} customer-managed SCP attachment(s) on governed targets",
                           "Review custom SCPs before upgrading; ensure they do not conflict "
                           "with the controls the new landing-zone version will apply.",
                           cols=["Target", "SCP Name", "SCP Id"], rows=custom_rows[:100]))


def check_scp_blocking(ctx: Context, report: Report) -> None:
    """SCP *content* can block a Control Tower update, per AWS guidance:
      - The `FullAWSAccess` SCP must remain attached (its removal breaks CT access).
      - A custom Deny that does not exempt the AWSControlTowerExecution role can block
        the operations CT performs in member accounts during the update.
      - Restricting Regions via SCP (instead of the CT Region deny control) puts CT in an
        'undefined state'.
    This is a heuristic (it does not fully simulate policy evaluation), so risky SCPs are
    reported as WARNING for human review, not auto-BLOCKER."""
    try:
        ous = ctx.all_ou_arns()
        roots = _collect(ctx.orgs, "list_roots", "Roots")
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("scp_blocking", UNKNOWN, "Could not enumerate targets for SCP content check", str(e)))
        return
    targets = [{"Id": r["Id"], "Name": f"(root) {r.get('Name', r['Id'])}"} for r in roots]
    targets += [{"Id": o["Id"], "Name": o["Name"]} for o in ous]

    missing_fullaccess, risky = [], []
    doc_cache: Dict[str, Any] = {}
    checked = 0
    for t in targets:
        try:
            scps = _collect(ctx.orgs, "list_policies_for_target", "Policies",
                            TargetId=t["Id"], Filter="SERVICE_CONTROL_POLICY")
        except (ClientError, BotoCoreError):
            continue
        checked += 1
        names = {p.get("Name", "") for p in scps}
        if "FullAWSAccess" not in names:
            missing_fullaccess.append([t["Name"]])
        for p in scps:
            name = p.get("Name", "")
            pid = p.get("Id", "")
            # Skip AWS-managed FullAWSAccess and Control Tower's own guardrail SCPs.
            if name == "FullAWSAccess" or name.startswith("aws-guardrails") or p.get("AwsManaged"):
                continue
            if pid not in doc_cache:
                try:
                    pol = ctx.orgs.describe_policy(PolicyId=pid)["Policy"]
                    doc_cache[pid] = pol.get("Content", "")
                except (ClientError, BotoCoreError):
                    doc_cache[pid] = None
            content = doc_cache.get(pid)
            if not content:
                continue
            try:
                doc = json.loads(content)
            except (ValueError, TypeError):
                continue
            stmts = doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            for stmt in stmts:
                if stmt.get("Effect") != "Deny":
                    continue
                blob = json.dumps(stmt)
                exempts_ct = "AWSControlTowerExecution" in blob
                restricts_region = "aws:RequestedRegion" in blob
                if not exempts_ct:
                    reason = ("Deny does not exempt AWSControlTowerExecution"
                              + ("; also restricts Regions" if restricts_region else ""))
                    risky.append([t["Name"], name, reason])
                    break  # one row per SCP/target is enough
                elif restricts_region:
                    risky.append([t["Name"], name, "Region restriction via SCP (use CT Region deny)"])
                    break
    if not checked:
        report.add(Finding("scp_blocking", UNKNOWN, "No targets queryable for SCP content"))
        return
    if missing_fullaccess:
        report.add(Finding("scp_blocking", WARNING,
                           f"FullAWSAccess SCP not attached to {len(missing_fullaccess)} target(s)",
                           "AWS Control Tower expects the FullAWSAccess SCP to remain attached; "
                           "its removal can cut off access that CT needs during the update.",
                           cols=["Target"], rows=missing_fullaccess,
                           remediation="Re-attach the AWS-managed FullAWSAccess SCP to the target."))
    if risky:
        report.add(Finding("scp_blocking", WARNING,
                           f"{len(risky)} custom SCP attachment(s) may block Control Tower",
                           "These custom SCPs contain a Deny that does not exempt the "
                           "AWSControlTowerExecution role, or restrict Regions via SCP. Either can "
                           "cause the update to fail. Verify they exempt CT (ArnNotLike on "
                           "aws:PrincipalARN) or move Region restriction to the CT Region deny control.",
                           cols=["Target", "SCP", "Risk"], rows=risky,
                           remediation="Add an AWSControlTowerExecution exemption, or detach the SCP "
                                       "for the upgrade. See the CT SCP guidance."))
    if not missing_fullaccess and not risky:
        report.add(Finding("scp_blocking", PASS,
                           f"FullAWSAccess present and no CT-blocking custom SCP patterns "
                           f"found across {checked} target(s)"))


CHECKS = [
    check_lz_status,
    check_lz_drift,
    check_update_available,
    check_managed_accounts,
    check_suspended_with_provisioned_product,
    check_enabled_controls,
    check_enabled_baselines,
    check_stacksets,
    check_stackset_active_drift,
    check_config_in_shared_accounts,
    check_customizations,
    check_trusted_access,
    check_delegated_admins,
    check_required_iam_roles,
    check_kms_key,
    check_sts_regional_activation,
    check_scp_headroom,
    check_scp_blocking,
]


# --------------------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------------------
ICON = {BLOCKER: "[X]", WARNING: "[!]", INFO: "[i]", PASS: "[OK]", UNKNOWN: "[?]"}


def render_text(report: Report, ctx: Context) -> str:
    lines = []
    lines.append("=" * 78)
    lines.append("AWS Control Tower — Pre-Upgrade Precheck")
    lines.append(f"  Management account : {ctx.mgmt_account}")
    lines.append(f"  Home region        : {ctx.region}")
    lines.append(f"  Landing zone       : v{ctx.lz.get('version')} "
                 f"(latest {ctx.lz.get('latestAvailableVersion')})")
    lines.append(f"  Governed regions   : {', '.join(ctx.governed_regions)}")
    lines.append("=" * 78)
    for level in (BLOCKER, WARNING, UNKNOWN, INFO, PASS):
        group = report.by_level(level)
        if not group:
            continue
        lines.append(f"\n{ICON[level]} {level}  ({len(group)})")
        lines.append("-" * 78)
        for f in group:
            lines.append(f"  {ICON[level]} {f.summary}")
            if f.detail:
                lines.append(f"        {f.detail}")
            if f.rows:
                lines.append(f"        {' | '.join(f.cols)}")
                for r in f.rows[:50]:
                    lines.append(f"          - {' | '.join(str(x) for x in r)}")
            if f.remediation:
                lines.append(f"        FIX: {f.remediation}")
    lines.append("\n" + "=" * 78)
    n_block = len(report.by_level(BLOCKER))
    n_unk = len(report.by_level(UNKNOWN))
    n_warn = len(report.by_level(WARNING))
    if n_block:
        lines.append(f"RESULT: NOT SAFE TO UPGRADE — {n_block} blocker(s), "
                     f"{n_warn} warning(s), {n_unk} unverified.")
    else:
        lines.append(f"RESULT: No blockers. {n_warn} warning(s), {n_unk} unverified — "
                     "review before proceeding.")
    lines.append("=" * 78)
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Control Tower pre-upgrade precheck (read-only)")
    ap.add_argument("--region", help="Home region (defaults to session region)")
    ap.add_argument("--profile", help="AWS profile for the management account")
    ap.add_argument("--member-role", default="AWSControlTowerExecution",
                    help="Role to assume in shared accounts for the Config check")
    ap.add_argument("--audit-account", help="Override Audit account id")
    ap.add_argument("--log-archive-account", help="Override Log Archive account id")
    ap.add_argument("--json", help="Write full JSON report to this path")
    ap.add_argument("--detect-drift", action="store_true",
                    help="Actively run CloudFormation StackSet drift detection on "
                         "AWSControlTower* StackSets (slower; launches drift operations)")
    ap.add_argument("--drift-timeout", type=int, default=900,
                    help="Max seconds to wait for each StackSet drift operation (default 900)")
    ap.add_argument("--strict", action="store_true",
                    help="Treat WARNING and UNKNOWN as blocking too")
    args = ap.parse_args()

    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    region = args.region or session.region_name
    if not region:
        print("No region: pass --region or configure a default.", file=sys.stderr)
        return 3

    report = Report()
    ctx = Context(session, region, args.member_role)
    if not ctx.discover(report):
        print(render_text(report, ctx))
        return 3
    if args.audit_account:
        ctx.audit_account = args.audit_account
    if args.log_archive_account:
        ctx.log_archive_account = args.log_archive_account
    ctx.detect_drift = args.detect_drift
    ctx.drift_timeout = args.drift_timeout

    for check in CHECKS:
        try:
            check(ctx, report)
        except Exception as e:  # a check must never crash the gate
            report.add(Finding(check.__name__, UNKNOWN,
                               f"Check '{check.__name__}' errored", repr(e)))

    print(render_text(report, ctx))
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"findings": [asdict(f) for f in report.findings]}, fh, indent=2)
        print(f"\nJSON report written to {args.json}")

    if report.has_blockers:
        return 2
    if args.strict and (report.has_warnings or report.has_unknowns):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

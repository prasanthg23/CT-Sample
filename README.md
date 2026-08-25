# AWS Control Tower Pre-Upgrade Precheck

![AWS](https://img.shields.io/badge/AWS-Control%20Tower-orange)
![Language](https://img.shields.io/badge/python-3.8%2B-blue)
![Access](https://img.shields.io/badge/access-read--only-brightgreen)
![License](https://img.shields.io/badge/license-MIT--0-green)

> **Disclaimer:** This code is provided as-is to demonstrate a concept or workflow for AWS
> customers. You are responsible for ensuring it meets your requirements and for thoroughly
> reviewing and testing it in a sandbox environment before running it against production.

A **read-only** command-line tool that you run **before** updating, repairing, or resetting an
AWS Control Tower landing zone. It confirms the environment is in a known-good state and reports
the issues, drift, out-of-band changes, and customizations that are the documented causes of
landing-zone update failures — **so you can fix them first and reduce failed upgrades.**

Updating a landing zone is meant to be routine, but the update **does not roll back** if it
fails, and it can leave the landing zone in an indeterminate state. Most failures are caused by a
small set of *detectable* preconditions (drift, suspended accounts with orphaned resources,
lingering AWS Config resources, custom StackSet instances in new Regions, and so on). This tool
checks for those preconditions and gates the upgrade with a non-zero exit code when it finds a
blocker.

## Table of Contents

- [Overview](#overview)
- [What it checks](#what-it-checks)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Sample output](#sample-output)
- [How it works](#how-it-works)
- [Limitations and scope](#limitations-and-scope)
- [FAQs](#faqs)
- [Security](#security)
- [Notices](#notices)
- [License](#license)

## Overview

The tool runs from the **AWS Control Tower management account** in the **home Region** and
performs a series of `List*` / `Get*` / `Describe*` / `Search*` calls. It:

- Verifies landing-zone health and **drift** status.
- Confirms whether an update is actually pending, and the version delta.
- Inspects **managed accounts**, **enabled controls**, and **enabled baselines** (including child
  accounts) for drift or non-successful states.
- Detects the **out-of-band changes** and **orphaned resources** that block updates.
- Flags **customizations** (CfCT, AFT, custom StackSets) you must account for.

Every finding is classified as one of:

| Level | Meaning |
|-------|---------|
| `BLOCKER` | Must be resolved before upgrading. Causes a non-zero exit code. |
| `WARNING` | Should be reviewed; may cause partial or downstream issues. |
| `UNKNOWN` | Could **not** be verified (missing permission or API error). Never assumed good. |
| `INFO` | Informational (e.g. customizations, version delta). |
| `PASS` | Verified good. |

## What it checks

Each check maps to a documented cause of landing-zone update failure or drift.

| # | Check | Detects | Data source (read-only) | Default severity |
|---|-------|---------|-------------------------|------------------|
| 1 | Landing zone status | `FAILED` / `PROCESSING` / mid-operation | `controltower:GetLandingZone` | BLOCKER |
| 2 | Landing zone drift | Out-of-band change / managed-SCP modification / moved shared account | `controltower:GetLandingZone` (`driftStatus`) | BLOCKER |
| 3 | Update availability | Version currency and delta | `controltower:GetLandingZone` (`version`, `latestAvailableVersion`) | INFO |
| 4 | Managed accounts | `SUSPENDED` accounts in the org | `organizations:ListAccounts` | WARNING |
| 5 | Orphaned provisioned products | Suspended account still holding an Account Factory product (→ `AWSControlTowerExecution` can't be assumed) | `organizations:ListAccounts` + `servicecatalog:SearchProvisionedProducts` | BLOCKER |
| 6 | Enabled controls drift | Drifted / non-`SUCCEEDED` controls across every registered OU | `organizations` (OU discovery) + `controltower:ListEnabledControls` | BLOCKER |
| 7 | Enabled baselines drift | Drifted / non-`SUCCEEDED` baselines incl. child accounts | `controltower:ListEnabledBaselines` (`includeChildren=true`) | BLOCKER |
| 8 | StackSet health | `AWSControlTower*` stack instances INOPERABLE/FAILED/DRIFTED. Only **shared-account** (mgmt/audit/log-archive) instances block; **member-account** instances are WARNING; instances for **departed accounts** are INFO. OUTDATED is INFO (normal before an update). | `cloudformation:ListStackSets` / `ListStackInstances` | BLOCKER / WARNING / INFO |
| 9 | AWS Config in shared accounts | Extra/foreign Config recorders in Audit & Log Archive (and non-home Regions) | `sts:AssumeRole` + `config:DescribeConfigurationRecorders` | WARNING |
| 10 | Customizations | CfCT / AFT / custom StackSets targeting governed Regions | `cloudformation` / `organizations` | INFO |
| 11 | Trusted access | Required Organizations trusted service access disabled | `organizations:ListAWSServiceAccessForOrganization` | BLOCKER |
| 12 | Delegated administrators | Conflicting delegated admins (CFN StackSets / Config) | `organizations:ListDelegatedAdministrators` / `ListDelegatedServicesForAccount` | INFO |
| 13 | Required IAM roles | Missing CT management-account service roles | `iam:GetRole` | BLOCKER |
| 14 | KMS key state | LZ customer-managed key disabled / pending deletion | `kms:DescribeKey` | BLOCKER |
| 15 | STS regional activation | STS deactivated in a governed Region (update fails midway) | `sts:GetCallerIdentity` (per Region) | BLOCKER |
| 16 | SCP headroom | Target at/near the 10-SCP limit + custom SCP inventory | `organizations:ListPoliciesForTarget` | WARNING |
| 17 | SCP blocking content | `FullAWSAccess` detached; custom Deny not exempting `AWSControlTowerExecution`; Region restriction via SCP | `organizations:ListPoliciesForTarget` / `DescribePolicy` | WARNING |
| 18 | In-progress StackSet operations | `RUNNING`/`STOPPING`/`QUEUED` operation on an `AWSControlTower*` StackSet (conflicts with the update) | `cloudformation:ListStackSetOperations` | BLOCKER |
| 19 | Foundational StackSets present | Core `AWSControlTower*` StackSets entirely **missing** (broken / partially-deleted landing zone — repair, don't upgrade) | `cloudformation:ListStackSets` | WARNING |
| 20 | Account Factory product health | Provisioned products in `ERROR`/`TAINTED` (inconsistent account — cannot update via Account Factory, can block controls on its OU; account-re-baselining issue, not an LZ-update blocker) or `UNDER_CHANGE`/`PLAN_IN_PROGRESS` (mid-flight) | `servicecatalog:SearchProvisionedProducts` | WARNING |

**Opt-in deeper checks** (off by default — slower or heuristic; enable with a flag):

| Flag | Check | Detects | Data source | Default severity |
|------|-------|---------|-------------|------------------|
| `--detect-drift` | Active StackSet drift | Actually runs CloudFormation drift detection on `AWSControlTower*` StackSets and reports **DRIFTED** instances with the drifted resource(s); without it, stored `DriftStatus` is only as fresh as the last run (often `NOT_CHECKED`) | `cloudformation:DetectStackSetDrift` / `DescribeStackSetOperation` / `DescribeStackResourceDrifts` | BLOCKER (shared) / WARNING (member) |
| `--check-member-roles` | Member execution-role sweep | Assumes into every enrolled account to confirm `AWSControlTowerExecution` exists/assumable (missing = role drift → LZ can become unavailable) | `sts:AssumeRole` per account | WARNING |
| `--check-kms-policy` | KMS key-policy | Landing-zone CMK key policy does not grant CT's `config`/`cloudtrail` service principals (heuristic) | `kms:GetKeyPolicy` | WARNING |
| `--check-orphaned-resources` | Recreate-collision scan | **When the LZ looks broken** (FAILED or a foundational StackSet missing), scans the shared accounts for baseline-created resources that still exist even though the StackSet that manages them is gone (IAM roles, Config recorder/delivery channel, SNS topics, CloudWatch log groups, `NotificationForwarder` Lambda, `ConfigComplianceChangeEventRule`, `BaselineCloudTrail`, `aws-controltower-*` S3 buckets) — these collide (`already exists`) when Repair/Reset recreates them | `sts:AssumeRole` + (in shared accounts) `iam:GetRole`, `config:DescribeConfigurationRecorders`/`DescribeDeliveryChannels`, `sns:ListTopics`, `logs:DescribeLogGroups`, `lambda:GetFunction`, `events:ListRules`, `cloudtrail:DescribeTrails`, `s3:ListAllMyBuckets` | WARNING |

> **Severity model.** Only issues in the **shared accounts** (management, log archive, audit) and
> org-level configuration **hard-block** the landing-zone update. The same issue in a **member**
> account is a **WARNING**, because a landing-zone update/repair/reset acts on the shared accounts
> and org config first — member accounts are re-baselined separately (via *Re-register OU*). With
> `--detect-drift`, active drift detection owns `DRIFTED` reporting and the stored-status check
> defers to it (no double-counting).

The required CT management-account IAM roles verified by check #13 are:
`AWSControlTowerAdmin`, `AWSControlTowerCloudTrailRole`, `AWSControlTowerStackSetRole`,
`AWSControlTowerConfigAggregatorRoleForOrganizations`.

## Prerequisites

- Python 3.8+ and `boto3` (see [`requirements.txt`](requirements.txt)).
- Credentials for the **Control Tower management account**, used in the **home Region**.
- A read-only permission set covering the actions in the table above. Minimum policy:

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": [
        "controltower:ListLandingZones",
        "controltower:GetLandingZone",
        "controltower:ListEnabledControls",
        "controltower:ListEnabledBaselines",
        "organizations:ListRoots",
        "organizations:ListOrganizationalUnitsForParent",
        "organizations:ListAccounts",
        "organizations:ListPolicies",
        "organizations:ListPoliciesForTarget",
        "organizations:DescribePolicy",
        "organizations:ListAWSServiceAccessForOrganization",
        "organizations:ListDelegatedAdministrators",
        "organizations:ListDelegatedServicesForAccount",
        "servicecatalog:SearchProvisionedProducts",
        "cloudformation:ListStackSets",
        "cloudformation:DescribeStackSet",
        "cloudformation:ListStackInstances",
        "cloudformation:ListStacks",
        "cloudformation:ListStackSetOperations",
        "cloudformation:DetectStackSetDrift",
        "cloudformation:DescribeStackSetOperation",
        "cloudformation:DescribeStackResourceDrifts",
        "iam:GetRole",
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "sts:GetCallerIdentity",
        "sts:AssumeRole"
      ],
      "Resource": "*"
    }]
  }
  ```

- (Optional, for check #9) A role assumable in the Audit and Log Archive accounts. The tool
  defaults to `AWSControlTowerExecution`, which the management account can already assume. If that
  role is unavailable, the check reports `UNKNOWN` rather than failing.

## Installation

```bash
git clone <your-fork-url> sample-controltower-preupgrade-precheck
cd sample-controltower-preupgrade-precheck
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# From the management account, home Region (uses ambient credentials/role):
python3 Source/ct_preupgrade_precheck.py

# Explicit Region / named profile:
python3 Source/ct_preupgrade_precheck.py --region us-east-1 --profile my-mgmt-admin

# Emit a JSON report and treat WARNING/UNKNOWN as blocking (strict gate):
python3 Source/ct_preupgrade_precheck.py --json report.json --strict

# Override shared account discovery if the manifest lookup is unavailable:
python3 Source/ct_preupgrade_precheck.py \
    --audit-account 111111111111 --log-archive-account 222222222222

# Opt-in deeper checks (slower / heuristic; off by default):
python3 Source/ct_preupgrade_precheck.py --detect-drift            # active StackSet drift detection
python3 Source/ct_preupgrade_precheck.py --check-member-roles      # assume into every enrolled account
python3 Source/ct_preupgrade_precheck.py --check-kms-policy        # verify CMK key policy grants CT services
python3 Source/ct_preupgrade_precheck.py --check-orphaned-resources # (broken LZ) find leftover resources that collide on Repair/Reset

# Output formatting:
python3 Source/ct_preupgrade_precheck.py --color always            # force color (e.g. when piping to a pager)
python3 Source/ct_preupgrade_precheck.py --color never             # disable color
```

The text report is color-coded by severity (BLOCKER red, WARNING yellow, UNVERIFIED magenta,
INFO cyan, PASS green), with `[X]`/`[!]`/`[?]`/`[i]`/`[OK]` markers kept as an accessible,
color-independent fallback. Color is applied only when the output is an interactive terminal
(`--color auto`, the default); it is suppressed automatically when the output is piped or
redirected, when `--color never` is used, or when the `NO_COLOR` environment variable is set. The
`--json` report is never colorized.

### Exit codes (for pipeline gating)

| Code | Meaning |
|------|---------|
| `0` | No blockers — safe to proceed (review any warnings). |
| `2` | One or more blockers — **do not upgrade** until resolved. |
| `3` | The precheck could not run (authentication/setup problem). |

Gate an upgrade runbook simply:

```bash
python3 Source/ct_preupgrade_precheck.py --strict || { echo "Precheck failed"; exit 1; }
```

## Sample output

```
==============================================================================
AWS Control Tower — Pre-Upgrade Precheck
  Management account : 123456789012
  Home region        : us-east-1
  Landing zone       : v3.3 (latest 4.0)
  Governed regions   : us-east-1, us-west-2
==============================================================================

[X] BLOCKER  (2)
------------------------------------------------------------------------------
  [X] Landing zone is DRIFTED (out-of-band change detected)
        Landing-zone level drift (e.g. a managed SCP was attached, detached, ...)
        FIX: Reset or update the landing zone to restore config. See .../drift.html
  [X] 1 provisioned product(s) still exist for suspended account(s)
        Account | Provisioned Product | Status
          - 333333333333 | account-factory-... | AVAILABLE
        FIX: Reopen+terminate the provisioned product, or remove orphaned StackSet instances.

[i] INFO  (2)
------------------------------------------------------------------------------
  [i] Update available: 3.3 -> 4.0

==============================================================================
RESULT: NOT SAFE TO UPGRADE — 2 blocker(s), 0 warning(s), 0 unverified.
==============================================================================
```

## How it works

1. **Discovery** — Finds the landing zone (`ListLandingZones` → `GetLandingZone`) and reads the
   landing-zone **manifest** to auto-discover the **governed Regions** and the **Audit** and
   **Log Archive** account IDs. No hard-coding required.
2. **Checks** — Runs each check independently. A check that errors is reported as `UNKNOWN`; it
   never crashes the run, so a single missing permission cannot hide the rest of the report.
3. **Report + gate** — Prints a grouped report (and optional JSON), then exits non-zero if any
   blocker (or, with `--strict`, any warning/unknown) is present.

## Testing

The blocker-detection logic is proven offline with a mocked-response harness — no AWS account
or network needed. It feeds each check simulated good/bad API responses and asserts the correct
severity fires (e.g. DRIFTED → BLOCKER, OUTDATED StackSet → INFO, unreachable shared account →
UNKNOWN not PASS, a Deny SCP without an `AWSControlTowerExecution` exemption → WARNING).

```bash
python3 tests/test_blocker_paths.py      # 59 tests, plain unittest (no extra deps)
```

This complements a live run against a healthy landing zone (which only exercises the PASS/INFO
paths): the harness proves the BLOCKER/WARNING/UNKNOWN paths without needing a broken
environment.

## Limitations and scope

This tool reduces upgrade failures; it does not guarantee success. Be aware of the following:

- **Some failures only surface at deploy time.** Runtime issues — KMS key/permission edge cases,
  a blueprint entering `UPDATE_FAILED`, service throttling — cannot be predicted by a read-only
  precheck. AWS Control Tower does not roll back a failed update, so always follow the
  [best practices for landing zone updates](https://docs.aws.amazon.com/controltower/latest/userguide/lz-update-best-practices.html).
- **`UNKNOWN` is not `PASS`.** If a permission is missing or an API errors, the affected check
  reports `UNKNOWN`. Treat unknowns as "must verify manually," and use `--strict` to gate on them.
- **The Config check requires cross-account access.** Check #9 assumes a role
  (`AWSControlTowerExecution` by default) into the shared accounts; without it the check is
  `UNKNOWN`, not silently skipped.
- **Customization detection is best-effort.** It uses naming heuristics (`CustomControlTower*`
  StackSets, AFT account naming) and can produce false negatives for heavily renamed deployments.
- **Region.** Control Tower is Region-scoped; run in the home Region or checks will not find the
  landing zone.

## FAQs

**Does this change anything in my environment?**
No. Every call is read-only (`List*`/`Get*`/`Describe*`/`Search*`). It cannot create, modify, or
delete resources.

**Where do I run it?**
The Control Tower **management account**, in the **home Region**.

**It reported a blocker for drift — what now?**
Resolve drift first (reset/update the landing zone, re-register OUs, or reset enabled
controls/baselines), then re-run the precheck until it is clean. See
[Detect and resolve drift in AWS Control Tower](https://docs.aws.amazon.com/controltower/latest/userguide/drift.html).

**Can I run it in a pipeline?**
Yes. Use `--json` for a machine-readable report and gate on the exit code (see above).

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for how to report a potential
security issue. This tool requires only read-only permissions; grant it a least-privilege,
read-only role and do not store long-lived credentials.

## Notices

Customers are responsible for making their own independent assessment of the information in this
sample. This sample: (a) is for informational purposes only, (b) represents current AWS product
offerings and practices, which are subject to change without notice, and (c) does not create any
commitments or assurances from AWS and its affiliates, suppliers, or licensors. AWS products or
services are provided "as is" without warranties, representations, or conditions of any kind,
whether express or implied.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.

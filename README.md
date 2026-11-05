# 🛡️ ChainBreak — Automated AWS Security Auditor

### *Finds the chain of small misconfigurations that combine into a real attack path*

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3.0-blue?style=for-the-badge\&logo=gnu\&logoColor=white)](https://www.gnu.org/licenses/gpl-3.0)
[![AWS](https://img.shields.io/badge/AWS-Lambda%20%7C%20DynamoDB%20%7C%20SNS-orange?style=for-the-badge\&logo=amazonaws\&logoColor=white)](https://aws.amazon.com)
[![Node.js](https://img.shields.io/badge/Node.js-20.x-339933?style=for-the-badge\&logo=node.js\&logoColor=white)](https://nodejs.org)
[![Terraform](https://img.shields.io/badge/Terraform-1.5+-7B42BC?style=for-the-badge\&logo=terraform\&logoColor=white)](https://www.terraform.io)
[![Tests](https://img.shields.io/badge/tests-108%20passing-brightgreen?style=for-the-badge\&logo=vitest\&logoColor=white)](#-testing)

---

## 📋 Table of Contents

- [The Problem](#-the-problem)
- [What ChainBreak Does](#-what-chainbreak-does)
- [Architecture](#-architecture)
- [How Scoring Works](#-how-scoring-works)
- [Safety Model](#-safety-model)
- [Tech Stack](#-tech-stack)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Testing](#-testing)
- [Demo Script](#-demo-script)
- [Project Structure](#-project-structure)
- [Build Status](#-build-status)
- [Known Limitations](#-known-limitations)
- [Cost](#-cost)
- [License](#-license)

---

## 🎯 The Problem

Cloud breaches are rarely one big mistake. They're a **chain of small, individually forgivable misconfigurations**:

```
Public EC2 instance            (fine on its own)
         +
Over-permissioned IAM role     (fine on its own)
         +
Open SSH on its security group (fine on its own)
         =
🚨 A REAL ATTACK PATH
```

Most scanners check resources one at a time and never see the combination. That gap is why CSPM companies like Wiz and Orca exist. ChainBreak is a small-scale, working version of the same idea.

---

## ✨ What ChainBreak Does

1. **Detects** misconfigurations — security groups exposing SSH/RDP to the internet, S3 buckets without public-access protection, unencrypted RDS storage
2. **Relates** them — maps every EC2 instance to its subnet's internet reachability and its IAM role's actual permissions
3. **Scores** the combination — a blast-radius score built from *relationships*, not single resources
4. **Fixes** what is provably safe — revokes a single-port SSH/RDP rule open to `0.0.0.0/0`
5. **Escalates** what isn't — anything with a large blast radius goes to a human by email, and is deliberately never auto-fixed
6. **Records** everything in DynamoDB, fixed or not
7. **Runs itself** on an EventBridge schedule

The interesting part is #4 vs #5. **Detecting more did not make it braver about fixing more** — it fixes narrowly and escalates broadly, on purpose.

---

## 🏗️ Architecture

```
EventBridge (cron)
      │
      ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Lambda — handler.js (orchestrator)                │
│                                                                     │
│  OBSERVE (parallel)                                                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌──────────────────┐ │
│  │ sgScanner  │ │ s3Scanner  │ │ rdsScanner │ │ iamRoleScanner   │ │
│  │ SSH/RDP to │ │ public     │ │ unencrypted│ │ instance → role  │ │
│  │ 0.0.0.0/0  │ │ buckets    │ │ storage    │ │ → policy JSON    │ │
│  └─────┬──────┘ └─────┬──────┘ └─────┬──────┘ └────────┬─────────┘ │
│        │              │              │                 │           │
│        └──────────────┴──────────────┘            relationships     │
│                       │                                 │           │
│                       ▼                                 ▼           │
│                 ┌───────────────────────────────────────────┐       │
│       SCORE     │         analysis/blastRadius.js           │       │
│                 │  findings + relationships → severity      │       │
│                 │  (pure logic, zero AWS calls)             │       │
│                 └──────────────────┬────────────────────────┘       │
│                                    │                               │
│                    ┌───────────────┴────────────────┐              │
│                    ▼                                ▼              │
│              LOW severity                     HIGH severity        │
│            (small blast radius)            (large blast radius)    │
│                    │                                │              │
│                    ▼                                ▼              │
│         remediation/remediateSG.js          escalate only —        │
│         revokes the exact rule              NEVER auto-fixed       │
│         (7 safety gates, dry-run                   │               │
│          by default)                               │               │
│                    │                                │              │
│                    └───────────────┬────────────────┘              │
│                                    ▼                               │
│                         storage/findingsRepo.js                    │
│                    every finding, remediated or not                │
│                                    │                               │
│                                    ▼                               │
│                            notify/alerts.js                        │
│                     email, HIGH severity listed first              │
└─────────────────────────────────────────────────────────────────────┘
      │                      │                        │
      ▼                      ▼                        ▼
  DynamoDB                  SNS                CloudWatch Logs
```

**Note on the VPC:** the Lambda does **not** run inside the project's VPC. The VPC is the *target being scanned*, not the host. A VPC-attached Lambda would need a NAT Gateway (~$32/month) or VPC endpoints to reach DynamoDB and SNS, which breaks the zero-cost requirement. Keeping it outside is the correct choice, not an oversight.

---

## 📊 How Scoring Works

`blastRadius.js` starts from a base score per finding type, then adds points for each relationship it can prove:

| Factor | Points |
|---|---|
| Open SSH/RDP port (base) | 5 |
| Public bucket / unencrypted RDS (base) | 4 |
| Attack path (base) | 8 |
| Instance is publicly reachable (public subnet **and** public IP) | +4 |
| Attached IAM role grants wildcard permissions | +3 |
| Attached IAM role grants full admin | +2 |
| Resource tagged `Sensitive=true` | +2 |

**Threshold: 12.** At or above it, a finding is `HIGH`, is escalated, and loses the right to be auto-remediated.

The threshold is tuned so that **no single factor can escalate a finding** — it takes a chain:

| Scenario | Score | Outcome |
|---|---|---|
| Open SSH on a group attached to nothing | 5 | LOW → auto-remediated |
| Open SSH + publicly reachable instance | 9 | LOW → auto-remediated (revoking is safe) |
| Open SSH + wildcard role, but private | 8 | LOW → auto-remediated |
| **Open SSH + public + wildcard role** | **12** | **HIGH → escalated to a human** |
| Public instance + admin role (no SG issue at all) | 14 | HIGH → reported as an `ATTACK_PATH` finding |

That last row is the signature feature: a finding that exists **only** as a combination, where no individual resource looks misconfigured.

One rule is absolute: **scoring can only ever take away the right to auto-remediate, never grant it.** An unencrypted RDS instance stays non-remediable however low it scores, because nothing here can fix it.

---

## 🔒 Safety Model

Auto-remediation is the only destructive capability, so it's fenced in:

- **One permission.** `ec2:RevokeSecurityGroupIngress` is the only non-read action in the IAM policy, scoped to security groups in this account and region. There is no `Authorize*` — the role can close an inbound hole but cannot open one.
- **Dry run by default.** `enable_remediation` defaults to `false`. The revoke path still runs, using AWS's own `DryRun` flag, which validates permissions and the exact rule match and then refuses to act. The whole path is provably correct before anything can delete a real rule.
- **Seven gates**, re-checked inside `remediateSG.js` even though the orchestrator already checked them — the cost of being wrong is a deleted firewall rule in a live account:
  1. finding is an `OPEN_PORT` finding
  2. the scanner marked it auto-remediable
  3. scoring did not escalate it to `HIGH`
  4. the IAM context was complete
  5. the group is not on the exclusion list
  6. port **and** CIDR are both whitelisted
  7. the rule is a **single-port TCP** rule matching the detected port
- **Fail closed.** An empty whitelist permits nothing. And if the IAM scan fails, every finding scores on base points alone, which looks `LOW` — so a failure in the *scoring* layer would make the system *more* willing to delete rules. Remediation is therefore suppressed entirely for any run where risk could not be scored.
- **Broad rules are escalated, not fixed.** "All traffic to `0.0.0.0/0`" is detected and scored, but never auto-revoked — removing it would strip every inbound rule, not just the exposure that was found.

---

## 🧰 Tech Stack

| Layer | Technology |
| :--- | :--- |
| IaC | Terraform (HCL), AWS provider ~> 5.0 |
| Networking | VPC, public/private subnets across 2 AZs, IGW, route tables, NACLs, security groups |
| Compute | AWS Lambda, Node.js 20.x |
| Scheduling | Amazon EventBridge |
| Storage | DynamoDB, `PAY_PER_REQUEST`, GSI on status |
| Alerting | Amazon SNS (email) |
| AWS SDK | v3, modular `@aws-sdk/client-*` packages |
| Testing | Vitest — 108 unit tests, zero AWS calls |
| Language | JavaScript, ES modules |

---

## 🚀 Quick Start

### Prerequisites

- Node.js ≥ 20, Terraform ≥ 1.5, AWS CLI configured, a Free-Tier-eligible AWS account

### 1. Install and test

```bash
git clone https://github.com/Amruth0-0/aws-security-auditor.git
cd aws-security-auditor
npm install
npm test
```

### 2. Package the Lambda

```bash
./scripts/package-lambda.sh
```

### 3. Deploy

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # then edit it
terraform init
terraform apply
```

`terraform.tfvars` needs at minimum `alert_email` and `my_ip`. Both are marked `sensitive` and have no defaults, so Terraform prompts for them if the file is missing.

### 4. Confirm the SNS subscription

**Check your email and click the confirmation link.** Until you do, the subscription sits in `PendingConfirmation` and alerts silently go nowhere. This is the single most common setup mistake.

### 5. Run it

The schedule is **disabled by default** (`enable_lambda = false`), so invoke it by hand first:

```bash
aws lambda invoke --function-name chainbreak-auditor --payload '{}' response.json && cat response.json
```

Expected shape:

```json
{
  "statusCode": 200,
  "body": "{\"message\":\"Scan completed successfully\",\"totalFindings\":3,\"highSeverity\":1,\"attackPaths\":1,\"instancesAnalysed\":1,\"openFindings\":2,\"remediated\":0,\"wouldRemediate\":1,\"remediationSuppressed\":false}"
}
```

`wouldRemediate: 1` with `remediated: 0` means dry run is working: it found something it *could* fix and deliberately didn't.

### 6. Tear down

```bash
terraform destroy
```

> ⚠️ `terraform destroy` does **not** remove the Lambda's CloudWatch log group — it is created implicitly by the Lambda service with no expiry. Delete `/aws/lambda/chainbreak-auditor` by hand if you want a truly clean account.

---

## ⚙️ Configuration

### Terraform variables

| Variable | Type | Default | Description |
| :--- | :---: | :--- | :--- |
| `project_name` | string | `chainbreak` | Prefix for all resource names |
| `aws_region` | string | `us-east-1` | Deployment region |
| `vpc_cidr` | string | `10.0.0.0/16` | VPC CIDR block |
| `availability_zones` | list(string) | `["us-east-1a","us-east-1b"]` | AZs for subnets |
| `alert_email` | string | *(required)* | SNS email destination |
| `my_ip` | string | *(required)* | Your IP for the demo EC2 security group |
| `rate_expression` | string | `rate(5 minutes)` | EventBridge schedule |
| `enable_lambda` | bool | `false` | **Enables the schedule** (not the function) |
| `enable_remediation` | bool | `false` | **Allows real revokes.** `false` = dry run only |
| `remediation_whitelist` | object | ports `[22,3389]`, cidrs `["0.0.0.0/0"]` | The only patterns eligible for auto-fix |
| `excluded_sg_ids` | list(string) | `[]` | Security groups never to touch |
| `severity_threshold` | number | `12` | Score at which a finding is escalated instead of fixed |

### Lambda environment variables

All set by Terraform from the values above — this is how config physically reaches the Node code.

| Variable | Source |
| :--- | :--- |
| `FINDINGS_TABLE_NAME` | `aws_dynamodb_table.findings.name` |
| `SNS_TOPIC_ARN` | `aws_sns_topic.alerts.arn` |
| `REMEDIATION_ENABLED` | `var.enable_remediation` |
| `REMEDIATION_WHITELIST` | `jsonencode(var.remediation_whitelist)` |
| `EXCLUDED_SG_IDS` | `join(",", var.excluded_sg_ids)` |
| `SEVERITY_THRESHOLD` | `var.severity_threshold` |

---

## 🧪 Testing

```bash
npm test
```

**108 unit tests, no AWS account needed, about one second.** The pure-logic layers are where the real coverage is:

| Suite | Tests | Covers |
| :--- | :---: | :--- |
| `sgScanner.test.js` | 19 | Port-range matching, all-traffic rules, IPv6, what counts as "the internet" |
| `blastRadius.test.js` | 28 | The chain — that no single factor escalates and a combination does |
| `remediateSG.test.js` | 28 | All seven safety gates, each with its refusal case |
| `iamRoleScanner.test.js` | 14 | Wildcard policy detection, URL-encoded policy documents |
| `handler.test.js` | 19 | Fault isolation, the decision pipeline, fail-closed behaviour |

Local integration against a real account, no deploy needed:

```bash
cp .env.example .env    # fill in from `terraform output`
npm run test:local
```

---

## 🎬 Demo Script

1. `terraform apply`, confirm the SNS email
2. Show the VPC, subnets and the clean security groups in the console
3. **Open SSH to `0.0.0.0/0`** on the `auditor-demo-sg` security group, by hand in the console
   *(`demo_target` has `lifecycle { ignore_changes = [ingress] }`, so Terraform won't fight you and won't report drift)*
4. Invoke the Lambda, show CloudWatch Logs: the finding is detected, scored, and dry-run remediated
5. Set `enable_remediation = true`, `terraform apply`, invoke again — **show the rule disappear from the console**
6. Show the DynamoDB record flip from `OPEN` to `REMEDIATED`
7. Launch a t2.micro in a **public** subnet with a role carrying `AdministratorAccess`
8. Invoke again — show the `ATTACK_PATH` finding and the `HIGH` severity email that explains *why*, and note that this one was **not** auto-fixed
9. `terraform destroy`

Step 8 is the one that demonstrates the thesis: no individual resource is misconfigured, and it's still reported as a real attack path.

---

## 📁 Project Structure

```
aws-security-auditor/
├── terraform/                  # Infrastructure as Code
│   ├── provider.tf             # AWS provider + version pin
│   ├── variables.tf            # Every configurable value
│   ├── outputs.tf              # Values needed after apply
│   ├── vpc.tf                  # VPC + 4 subnets across 2 AZs
│   ├── routing.tf              # IGW + route tables
│   ├── nacl.tf                 # Subnet-level firewall
│   ├── security_groups.tf      # Includes the demo target group
│   ├── iam.tf                  # Role, read-only policy, + the one revoke permission
│   ├── dynamodb.tf             # Findings table + status GSI
│   ├── lambda.tf               # Function, env vars, retry config
│   ├── eventbridge.tf          # Schedule + invoke permission
│   ├── sns.tf                  # Topic + email subscription
│   └── terraform.tfvars.example
│
├── src/
│   ├── handler.js              # Lambda entrypoint — sequencing and failure policy
│   ├── config/env.js           # The only reader of process.env
│   ├── scanners/
│   │   ├── sgScanner.js        # Open SSH/RDP detection
│   │   ├── s3Scanner.js        # Public bucket detection
│   │   ├── rdsScanner.js       # Unencrypted storage detection
│   │   └── iamRoleScanner.js   # Instance → subnet → role → policy relationships
│   ├── analysis/blastRadius.js # Scoring engine (pure)
│   ├── remediation/remediateSG.js  # The ONLY destructive code in the project
│   ├── storage/findingsRepo.js # DynamoDB wrapper
│   ├── notify/alerts.js        # SNS publisher
│   └── utils/logger.js         # (placeholder — see Known Limitations)
│
├── test/
│   ├── unit/                   # 108 tests, zero AWS calls
│   └── local/                  # Real-account scripts, no deploy
│
└── scripts/
    ├── package-lambda.sh       # Build dist/lambda.zip
    └── invoke-test.sh          # Invoke + tail logs
```

---

## 📈 Build Status

| Phase | Feature | Status |
|:---:|---|:---:|
| 0 | Environment setup | ✅ |
| 1 | VPC, subnets, NACLs, security groups | ✅ |
| 2 | IAM role, read-only | ✅ |
| 3 | Scanners — SG, S3, RDS | ✅ |
| 4 | DynamoDB findings storage + GSI | ✅ |
| 5 | SNS email alerting | ✅ |
| 6 | EventBridge scheduling | ✅ |
| 7 | Auto-remediation, dry-run by default | ✅ |
| 8 | Blast radius analysis + attack paths | ✅ |
| 9 | Docs, demo recording | 📹 Recording pending |

Built in the order above on purpose: **no destructive permission existed until the detection logic had been proven in read-only mode.** Phase 7 added exactly one write action, and nothing else.

---

## ⚠️ Known Limitations

Honest list of what this does **not** do:

- **Repeat alerts.** Every run emails all currently-open findings. With `rate(5 minutes)` that is a lot of identical email. There is no "only alert on new findings" suppression and no reconciliation that closes a finding fixed by hand — it stays `OPEN` and keeps being reported. *Next thing to build.*
- **S3 region handling.** `GetPublicAccessBlock` must be called against the bucket's own region; the client is pinned to one. Buckets elsewhere fail into a warning and currently read as clean.
- **S3 false positives.** A missing public-access-block config is reported as public without consulting `GetBucketPolicyStatus`, so account-level Block Public Access produces noise.
- **No graph beyond EC2.** The relationship model covers instance → subnet → role → policy. It does not yet model "which roles can read this specific bucket", so S3 and RDS findings score on base points alone.
- **Structured logging.** `logger.js` is still a placeholder; the code uses `console.log`. Works, but not greppable in CloudWatch Logs Insights.
- **No CI.** No GitHub Actions workflow running `terraform fmt -check`, `terraform validate` and `npm test`.
- **Log retention.** The Lambda log group is created implicitly with no expiry and survives `terraform destroy`.
- **`terraform fmt`.** Formatting is inconsistent across the `.tf` files.

---

## 💰 Cost

Designed to run at **$0/month** inside the AWS Free Tier:

| Service | Usage | Cost |
|---|---|---|
| Lambda | 128 MB, ~2s, every 5 min = ~8,600 invocations/month | $0 (1M free) |
| DynamoDB | `PAY_PER_REQUEST`, a few hundred writes/month | $0 (25 GB free) |
| SNS | Email notifications | $0 (1,000 free) |
| EventBridge | Scheduled rule | $0 |
| CloudWatch Logs | Small volume | $0 (5 GB free) |
| VPC, subnets, IGW, NACLs, security groups | — | $0 |

**Deliberately excluded:** NAT Gateway (~$32/month), EKS, persistent EC2, any hosted frontend. The optional demo EC2 is `t2.micro` and destroyed after recording.

---

## 📄 License

[GNU General Public License v3.0](LICENSE)

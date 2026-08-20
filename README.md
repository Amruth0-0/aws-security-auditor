# 🛡️ VanGuard — Automated AWS Security Auditor

### *First Line of Defense for Your Cloud*

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3.0-blue?style=for-the-badge\&logo=gnu\&logoColor=white)](https://www.gnu.org/licenses/gpl-3.0)
[![AWS](https://img.shields.io/badge/AWS-Lambda%20%7C%20DynamoDB%20%7C%20SNS-orange?style=for-the-badge\&logo=amazonaws\&logoColor=white)](https://aws.amazon.com)
[![Node.js](https://img.shields.io/badge/Node.js-20.x-339933?style=for-the-badge\&logo=node.js\&logoColor=white)](https://nodejs.org)
[![Terraform](https://img.shields.io/badge/Terraform-1.5+-7B42BC?style=for-the-badge\&logo=terraform\&logoColor=white)](https://www.terraform.io)
[![AWS Lambda](https://img.shields.io/badge/Serverless-AWS%20Lambda-FF9900?style=for-the-badge\&logo=awslambda\&logoColor=white)](https://aws.amazon.com/lambda/)
[![Infrastructure as Code](https://img.shields.io/badge/Infrastructure-Terraform-7B42BC?style=for-the-badge\&logo=terraform\&logoColor=white)](https://www.terraform.io)
---

## 📋 Table of Contents

- [🎯 Problem & Solution](#-problem--solution)
- [✨ Features](#-features)
- [🏗️ Architecture](#%EF%B8%8F-architecture)
- [🧰 Tech Stack](#-tech-stack)
- [🚀 Quick Start](#-quick-start)
- [⚙️ Configuration](#%EF%B8%8F-configuration)
- [📡 API Reference](#-api-reference)
- [🔒 Security Model](#-security-model)
- [📁 Project Structure](#-project-structure)
- [📊 Current Status](#-current-status)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## 🎯 Problem & Solution

### ❌ The Problem

Cloud security breaches are rarely caused by a single, obvious mistake. They're the result of a **chain of small, individually forgivable misconfigurations** that combine into something dangerous.

```
Public EC2 instance (fine on its own)
         +
Over‑permissioned IAM role (fine on its own)
         +
Access to sensitive S3 bucket (fine on its own)
         =
🚨 REAL ATTACK PATH
```

**Most security scanners check resources one at a time and miss these combinations.**

### ✅ The Solution

**VanGuard** delivers a zero-cost, serverless security auditor that:

- **Detects** misconfigurations across EC2, S3, and RDS
- **Traces relationships** between findings to identify real attack paths
- **Auto‑remediates** low‑risk findings (SSH/RDP open to 0.0.0.0/0)
- **Alerts** via email with actionable, human‑readable summaries
- **Runs automatically** on a schedule via EventBridge
- **Costs $0/month** — all within AWS Free Tier

---

## ✨ Features

- 🔍 **Automated Scanning** — Detects open SSH/RDP, public S3 buckets, and unencrypted RDS instances
- 💾 **Persistent Storage** — Findings stored in DynamoDB with status tracking (OPEN → REMEDIATED)
- 📧 **Email Alerts** — Real‑time SNS notifications with formatted findings summaries
- ⏰ **Scheduled Execution** — EventBridge cron trigger for hands‑off automated scanning
- 🔧 **Auto‑Remediation** — Safely revokes SSH/RDP rules open to 0.0.0.0/0
- 🔬 **Blast Radius Analysis** — Traces attack paths via IAM relationship scoring
- 🛡️ **Least‑Privilege IAM** — Scoped permissions following security best practices
- 🚀 **Zero Maintenance** — Deploy, demo, destroy — nothing left running
- 💰 **Zero Cost** — Fully AWS Free Tier compatible

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         EventBridge (Cron Schedule)                        │
│                      Every 5 minutes (demo) / Hour (idle)                  │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │ invokes
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Lambda Function (Node.js 20.x)                     │
│                                                                             │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────────────────────┐  │
│  │   sgScanner   │  │   s3Scanner   │  │     rdsScanner                │  │
│  │  SSH/RDP open │  │ Public bucket │  │  Unencrypted RDS              │  │
│  │  to 0.0.0.0/0 │  │  detection    │  │  instance detection           │  │
│  └───────┬───────┘  └───────┬───────┘  └───────────────┬───────────────┘  │
│          │                  │                          │                   │
│          └──────────────────┼──────────────────────────┘                   │
│                             ▼                                              │
│                    ┌─────────────────────┐                                │
│                    │  findingsRepo       │                                │
│                    │  save()             │                                │
│                    └─────────┬───────────┘                                │
│                              │                                             │
│                              ▼                                             │
│                    ┌─────────────────────┐                                │
│                    │  getByStatus()      │                                │
│                    │  "OPEN"             │                                │
│                    └─────────┬───────────┘                                │
│                              │                                             │
│           ┌──────────────────┼─────────────────────┐                      │
│           │                  │                     │                      │
│           ▼                  ▼                     ▼                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────────────────┐  │
│  │   SNS Alert     │  │   DynamoDB      │  │   CloudWatch Logs        │  │
│  │   (Email)       │  │   (Findings)    │  │   (Audit Trail)          │  │
│  └─────────────────┘  └─────────────────┘  └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **EventBridge** triggers the Lambda on a cron schedule
2. **Lambda** runs all scanners in parallel (SG, S3, RDS)
3. **Findings** are saved to DynamoDB via `findingsRepo.save()`
4. **GSI Query** `getByStatus("OPEN")` retrieves open findings
5. **SNS Alert** publishes a formatted email if open findings exist
6. **CloudWatch Logs** captures execution details for audit

---

## 🧰 Tech Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Infrastructure as Code** | Terraform (HCL) | Provision all AWS resources |
| **Networking** | AWS VPC, subnets, NACLs, IGW | Secure network isolation |
| **Compute** | AWS Lambda (Node.js 20.x) | Serverless execution engine |
| **Scheduling** | Amazon EventBridge | Cron‑based invocation |
| **Storage** | Amazon DynamoDB (PAY_PER_REQUEST) | Findings persistence |
| **Alerting** | Amazon SNS (Email) | Notifications |
| **AWS SDK** | v3 (modular clients) | Cloud API interactions |
| **Testing** | Vitest, local Node scripts | Unit & integration tests |
| **Language** | JavaScript (ES Modules) | Application logic |

---

## 🚀 Quick Start

Get VanGuard running in under 5 minutes.

### Prerequisites

- **Node.js** ≥ `20.x`
- **Terraform** ≥ `1.5`
- **AWS CLI** — configured with credentials
- **AWS Account** — Free Tier eligible

### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/vanguard.git
cd vanguard
```

### Step 2: Install Dependencies

```bash
npm install
```

### Step 3: Configure AWS Credentials

```bash
aws configure
# Enter your Access Key ID, Secret Key, region (us-east-1), and output format (json)

# Verify credentials
aws sts get-caller-identity
```

### Step 4: Package Lambda Code

```bash
./scripts/package-lambda.sh
```

This creates `dist/lambda.zip` with all source code and production dependencies.

### Step 5: Deploy Infrastructure

```bash
cd terraform
terraform apply
```

**You will be prompted for:**
- `alert_email` — Enter the email address for SNS notifications

**What gets created:**
- VPC with public/private subnets, IGW, route tables, NACLs
- IAM role with read‑only permissions
- DynamoDB table with GSI
- SNS topic with email subscription
- Lambda function with environment variables

### Step 6: Confirm SNS Subscription

Check your email inbox. You'll receive a confirmation email from AWS with subject:

> **"AWS Notification — Subscription Confirmation"**

**Click the confirmation link** before alerts will be delivered.

### Step 7: Run the Scanner

```bash
aws lambda invoke --function-name vanguard-auditor --payload '{}' response.json
cat response.json
```

Expected output:
```json
{
    "statusCode": 200,
    "body": "{\"message\":\"Scan completed successfully\",\"totalFindings\":2,\"openFindings\":2}"
}
```

### Step 8: Check Your Email

You should receive an alert with any open security findings.

### Step 9: Clean Up

```bash
terraform destroy
```

---

## ⚙️ Configuration

### Terraform Variables (`terraform/terraform.tfvars`)

| Parameter | Type | Default | Description |
| :--- | :---: | :--- | :--- |
| `project_name` | `string` | `vanguard` | Prefix for all resource names |
| `aws_region` | `string` | `us-east-1` | AWS region for deployment |
| `vpc_cidr` | `string` | `10.0.0.0/16` | CIDR block for the VPC |
| `availability_zones` | `list(string)` | `["us-east-1a", "us-east-1b"]` | AZs for subnets |
| `alert_email` | `string` | _(required)_ | Email for SNS notifications |
| `my_ip` | `string` | _(optional)_ | Your IP for SSH access (security group rule) |

### Environment Variables (Lambda)

| Parameter | Source | Description |
| :--- | :--- | :--- |
| `FINDINGS_TABLE_NAME` | `aws_dynamodb_table.findings.name` | DynamoDB table name |
| `SNS_TOPIC_ARN` | `aws_sns_topic.alerts.arn` | SNS topic ARN for alerts |

---

## 📡 API Reference

### Lambda Handler (`src/handler.js`)

The Lambda entrypoint orchestrates the entire scan pipeline.

**Event Payload:** `{}` (EventBridge invokes with an empty event)

**Response:**
```json
{
    "statusCode": 200,
    "body": "{\"message\":\"Scan completed successfully\",\"totalFindings\":2,\"openFindings\":2}"
}
```

### Storage Module (`src/storage/findingsRepo.js`)

| Method | Parameters | Returns | Description |
| :--- | :--- | :--- | :--- |
| `save(finding)` | `finding: Object` | `finding: Object` | Persists a finding to DynamoDB with deterministic `findingId` |
| `getAll()` | None | `Array<Finding>` | Retrieves all findings (for testing only) |
| `getByStatus(status)` | `status: string` | `Array<Finding>` | Queries GSI for findings with specific status |

### Alert Module (`src/notify/alerts.js`)

| Method | Parameters | Returns | Description |
| :--- | :--- | :--- | :--- |
| `publishAlert(findings)` | `findings: Array<Finding>` | `void` | Publishes formatted email via SNS |

---

## 🔒 Security Model

- **Least‑Privilege IAM** — Lambda execution role only has required permissions
- **Scoped Resources** — DynamoDB and SNS permissions limited to specific ARNs
- **Read‑Only First** — Detection logic proven before write permissions added
- **Narrow Auto‑Remediation** — Only revokes SSH/RDP to 0.0.0.0/0, nothing else
- **No Persistent Infrastructure** — Deploy, demo, destroy pattern
- **Zero Cost** — All resources within AWS Free Tier limits

---


## 📁 Project Structure

```
vanguard/
├── 📄 README.md                    # This file
├── 📄 .gitignore                   # Git ignore rules
├── 📄 package.json                 # Node.js dependencies
│
├── 🗺️ terraform/                   # Infrastructure as Code
│   ├── provider.tf                 # AWS provider configuration
│   ├── variables.tf                # All configurable values
│   ├── outputs.tf                  # Exported values
│   ├── vpc.tf                      # VPC, subnets, IGW
│   ├── routing.tf                  # Route tables
│   ├── nacl.tf                     # Network ACLs
│   ├── security_groups.tf          # Security groups
│   ├── iam.tf                      # IAM roles and policies
│   ├── dynamodb.tf                 # DynamoDB table + GSI
│   ├── lambda.tf                   # Lambda function
│   ├── eventbridge.tf              # Scheduled trigger
│   ├── sns.tf                      # SNS topic + subscription
│   └── terraform.tfvars.example    # Example variable values
│
├── 📦 src/                         # Application Source
│   ├── handler.js                  # Lambda entrypoint (orchestrator)
│   ├── config/
│   │   └── env.js                  # Centralized environment config
│   ├── scanners/
│   │   ├── sgScanner.js            # Security group scanner
│   │   ├── s3Scanner.js            # S3 bucket scanner
│   │   ├── rdsScanner.js           # RDS instance scanner
│   │   └── iamRoleScanner.js       # IAM role analyzer (Phase 8)
│   ├── storage/
│   │   └── findingsRepo.js         # DynamoDB wrapper
│   ├── notify/
│   │   └── alerts.js               # SNS publisher
│   ├── analysis/
│   │   └── blastRadius.js          # Severity scoring (Phase 8)
│   ├── remediation/
│   │   └── remediateSG.js          # Auto‑remediation (Phase 7)
│   └── utils/
│       └── logger.js               # Structured logging
│
├── 🧪 test/                        # Testing
│   ├── local/
│   │   ├── runLocalScan.js         # Local development loop
│   │   ├── testFindingsRepo.js     # Storage tests
│   │   └── testGetByStatus.js      # GSI query tests
│   └── unit/
│       ├── sgScanner.test.js
│       └── blastRadius.test.js
│
└── 🔧 scripts/
    ├── package-lambda.sh           # Package Lambda code
    └── invoke-test.sh              # Test Lambda invocation
```

---

## 📊 Current Status

### ✅ What's Working (Phases 0-6)

| Phase | Feature | Status |
|-------|---------|--------|
| 0 | Environment Setup | ✅ Complete |
| 1 | VPC, Subnets, NACLs, Security Groups | ✅ Complete |
| 2 | IAM Role with Read‑Only Permissions | ✅ Complete |
| 3 | Scanners (SG, S3, RDS) | ✅ Complete |
| 4 | DynamoDB Storage + GSI | ✅ Complete |
| 5 | SNS Alerting (Email) | ✅ Complete |
| 6 | EventBridge Scheduling | ✅ Complete |

**The core system works end‑to‑end:**
- ✅ Detects misconfigurations
- ✅ Saves to DynamoDB
- ✅ Queries OPEN findings via GSI
- ✅ Sends email alerts via SNS
- ✅ Runs automatically on schedule
- ✅ Costs $0/month (AWS Free Tier)

### 🚧 What's Being Built (Phases 7-9)

| Phase | Feature | Status |
|-------|---------|--------|
| 7 | Auto‑Remediation (revoke SSH/RDP rules) | 🔄 In Progress |
| 8 | Blast Radius Analysis (IAM relationship scoring) | 📋 Planned |
| 9 | Demo Packaging (docs, video, cleanup) | 📋 Planned |

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-cool-feature`.
3. Commit your changes: `git commit -m 'feat: add my cool feature'`.
4. Push to your branch: `git push origin feature/my-cool-feature`.
5. Open a Pull Request.

Please ensure your code passes all tests before opening PRs:

```bash
npm test
```

---

## 📄 License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

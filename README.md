# AWS Detection-as-Code Pipeline

![AWS](https://img.shields.io/badge/AWS-Detection%20Engineering-orange?style=for-the-badge&logo=amazon-aws)
![Terraform](https://img.shields.io/badge/Terraform-IaC-purple?style=for-the-badge&logo=terraform)
![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge)
![Sigma](https://img.shields.io/badge/Sigma-Detection%20Rules-yellow?style=for-the-badge)
![CI/CD](https://img.shields.io/badge/GitHub%20Actions-CI%2FCD-green?style=for-the-badge&logo=github)

## Overview

A production-grade Detection-as-Code pipeline that deploys version-controlled Sigma detection rules to AWS via Terraform Infrastructure as Code. Every detection rule is mapped to a MITRE ATT&CK technique, validated through a CI/CD pipeline on every push, and wired to an intelligent Lambda handler that enriches alerts with threat context before delivering structured notifications.

**This is not a manual SIEM configuration. This is detection engineering treated as software — versioned, tested, automated, and auditable.**

---

## Architecture
---

## MITRE ATT&CK Coverage

| Rule | Technique ID | Tactic | Severity |
|---|---|---|---|
| Root Account API Call | T1078 | Privilege Escalation | CRITICAL |
| IAM Policy Modification | T1484 | Privilege Escalation / Defense Evasion | HIGH |
| Suspicious S3 Access | T1537 | Exfiltration | MEDIUM |
| CloudTrail Logging Disabled | T1562 | Defense Evasion | CRITICAL |
| New IAM User Created | T1136 | Persistence | HIGH |

---

## What Makes This Detection-as-Code

### Version-Controlled Detection Rules
Every Sigma rule lives in `sigma-rules/mitre/` as a YAML file. Changes go through Git — every modification is tracked, reviewable, and reversible. No manual console changes.

### CI/CD Validation Pipeline
GitHub Actions runs three jobs on every push:
- **Sigma rule validation** — checks all required fields, YAML syntax, and MITRE tags
- **Terraform validation** — format check, init, and validate
- **MITRE coverage report** — generates a full report of techniques covered

### MITRE ATT&CK Enrichment
The Lambda handler maps every alarm to its MITRE technique, tactic, and reference URL. Every alert includes recommended response actions based on severity — CRITICAL gets immediate investigation steps, HIGH gets 1-hour SLA guidance, MEDIUM gets 4-hour guidance.

### Infrastructure as Code
19 AWS resources deployed with a single `terraform apply`:
- CloudWatch log group with 30-day retention
- 5 CloudWatch metric filters (the detection logic)
- 5 CloudWatch alarms (the trigger layer)
- EventBridge rule routing alarms to Lambda
- Lambda function with MITRE enrichment
- SNS topic with email subscription
- Least-privilege IAM role and policy

---

## Detection Rules

### T1078 — Root Account Usage (CRITICAL)
Fires when AWS root account credentials are used for any API call. Root usage is a critical security violation — production environments should never use root credentials for API operations.

### T1484 — IAM Policy Modification (HIGH)
Detects modifications to IAM policies including PutUserPolicy, PutRolePolicy, AttachUserPolicy, AttachRolePolicy, and CreatePolicy. Potential indicator of privilege escalation attempts.

### T1537 — Suspicious S3 Access (MEDIUM)
Detects unusual S3 access patterns including GetObject, ListBucket, and GetBucketAcl calls from non-service principals. Potential indicator of data exfiltration.

### T1562 — CloudTrail Disabled (CRITICAL)
Fires immediately when CloudTrail logging is stopped, deleted, or modified. A critical defense evasion indicator — attackers disable audit trails to blind defenders.

### T1136 — New IAM User Created (HIGH)
Detects creation of new IAM users which may indicate an attacker establishing persistence via a backdoor account.

---

## Tech Stack

| Category | Technology |
|---|---|
| Detection Format | Sigma (YAML) |
| Cloud Platform | AWS (us-east-1) |
| Infrastructure as Code | Terraform v5.x |
| Detection Logic | CloudWatch Metric Filters |
| Alerting | CloudWatch Alarms + SNS |
| Enrichment | Python 3.11 Lambda (boto3) |
| Orchestration | Amazon EventBridge |
| CI/CD | GitHub Actions |
| Framework | MITRE ATT&CK |

---

## Project Structure
---

## Deployment

```bash
git clone https://github.com/MarioMM21/aws-detection-as-code.git
cd aws-detection-as-code
terraform init
terraform plan
terraform apply
```

## Destroy

```bash
terraform destroy
```

---

## CI/CD Pipeline

Three automated jobs run on every push to main:

**Job 1 — Validate Sigma Rules**
Parses every YAML file in sigma-rules/mitre/ and validates required fields, syntax, and MITRE tags. Fails the pipeline if any rule is malformed.

**Job 2 — Validate Terraform**
Runs terraform fmt -check, terraform init -backend=false, and terraform validate. Ensures infrastructure code is always deployable.

**Job 3 — MITRE Coverage Report**
Generates a full report of MITRE ATT&CK techniques covered by the detection library. Published as a CI artifact on every push.

---

## Key Skills Demonstrated

| Skill | Evidence |
|---|---|
| **Detection Engineering** | 5 Sigma rules mapped to MITRE ATT&CK techniques |
| **Detection-as-Code** | Version-controlled rules deployed via Terraform + CI/CD |
| **Infrastructure as Code** | 19 AWS resources deployed with single terraform apply |
| **Python Security Automation** | Lambda handler with MITRE enrichment and severity routing |
| **CI/CD Pipeline** | GitHub Actions validating rules and infrastructure on every push |
| **MITRE ATT&CK Framework** | T1078, T1484, T1537, T1562, T1136 implemented |
| **CloudWatch Engineering** | Metric filters, alarms, and log group with retention |
| **Event-Driven Architecture** | EventBridge routing alarms to Lambda handler |
| **IAM Least Privilege** | Scoped Lambda role — no wildcard permissions |
| **Threat Intelligence** | Each rule includes false positive guidance and response actions |

---

## Project Progression

| Project | Focus | Resources |
|---|---|---|
| [AWS CSPM Pipeline](https://github.com/MarioMM21/aws-cspm-pipeline) | Cloud posture management + auto-remediation | 32 resources |
| [Enterprise Cloud Security Platform](https://github.com/MarioMM21/enterprise-cloud-security) | Enterprise security ops + severity routing | 52 resources |
| **AWS Detection-as-Code Pipeline** (this) | Detection engineering + MITRE ATT&CK coverage | 19 resources |

---

## Author

**Mario Myles**
Cloud Security Engineer | AWS | Terraform | Python | Detection Engineering | Security+

- GitHub: [github.com/MarioMM21](https://github.com/MarioMM21)
- LinkedIn: [linkedin.com/in/mario-myles](https://linkedin.com/in/mario-myles)

---

*Built and deployed May 2026*
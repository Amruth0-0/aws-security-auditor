# Demo

**Video:** _not yet recorded — add the link here._

A 2–3 minute screen recording (OBS) is the primary demo artifact for this
project. There is no hosted dashboard by design: the AWS Console plus this
recording is the interface, which removes all ongoing hosting and maintenance
risk for a project with no real users.

---

## Recording checklist

Run through these in order. Steps 5 and 8 are the two moments that matter.

| # | Action | What to show on screen |
|:---:|---|---|
| 1 | `terraform apply` | Resources being created; then click the SNS confirmation email |
| 2 | Console → VPC | Subnets across 2 AZs, route tables, NACLs |
| 3 | Console → Security Groups | `auditor-safe-sg` and `auditor-demo-sg`, both clean |
| 4 | **Manually** add SSH from `0.0.0.0/0` to `auditor-demo-sg` | The bad rule being created by hand — this keeps the demo authentic |
| 5 | `./scripts/invoke-test.sh` | Log shows the finding detected, scored LOW, and **dry-run** remediated (`wouldRemediate: 1`, `remediated: 0`) |
| 6 | Set `enable_remediation = true`, `terraform apply`, invoke again | **The rule disappears from the console.** This is the self-healing moment |
| 7 | Console → DynamoDB → `chainbreak-findings` | The record flipping `OPEN` → `REMEDIATED` |
| 8 | Launch a `t2.micro` in a **public** subnet with an `AdministratorAccess` role, then invoke | The `ATTACK_PATH` finding, and the HIGH severity email explaining *why* — **and that this one was not auto-fixed** |
| 9 | `terraform destroy` | Clean teardown |

---

## The two points worth narrating

**Step 6 — it fixes things itself.** The rule was added by hand and removed by
the auditor, with no human involved.

**Step 8 — it knows when not to.** Nothing in step 8 is individually
misconfigured: a public instance is normal, and an IAM role is normal. The
finding exists *only* as a combination. And unlike step 6, the auditor
deliberately refuses to fix it, because narrowing an IAM policy is a judgement
call about what the workload legitimately needs.

That contrast — automating the reversible, escalating the consequential — is the
design decision the whole project is built around, and it is what makes step 8
worth more than step 6.

---

## Architecture diagram

`docs/architecture-diagram.png` is currently a placeholder. The ASCII diagram in
the README is the current source of truth; export a cleaner version (draw.io or
Excalidraw) before publishing the video.

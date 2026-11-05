import { scan as scanSG } from "../../src/scanners/sgScanner.js";
import { scan as scanS3 } from "../../src/scanners/s3Scanner.js";
import { scan as scanRDS } from "../../src/scanners/rdsScanner.js";
import { scan as scanIamRoles } from "../../src/scanners/iamRoleScanner.js";
import { scoreAll, buildAttackPathFindings } from "../../src/analysis/blastRadius.js";
import { checkWhitelist, fix as remediateSG } from "../../src/remediation/remediateSG.js";
import { save, getAll, getByStatus } from "../../src/storage/findingsRepo.js";
import config from "../../src/config/env.js";

const LINE = "=".repeat(60);

async function safeScan(name, fn) {
    try {
        return { name, ok: true, value: await fn() };
    } catch (error) {
        console.error(`   ❌ ${name} failed: ${error.message}`);
        return { name, ok: false, value: [] };
    }
}

async function main() {
    console.log("🔍 ChainBreak — Local Full-Pipeline Scan");
    console.log("📅", new Date().toISOString());
    console.log(LINE);

    // ---- 1. Observe ------------------------------------------------------
    console.log("\n1️⃣  Scanning resources...");
    const [sg, s3, rds, iam] = await Promise.all([
        safeScan("sgScanner", scanSG),
        safeScan("s3Scanner", scanS3),
        safeScan("rdsScanner", scanRDS),
        safeScan("iamRoleScanner", scanIamRoles)
    ]);

    const rawFindings = [...sg.value, ...s3.value, ...rds.value];
    const contexts = iam.value;

    console.log(`   Security groups : ${sg.value.length} finding(s)`);
    console.log(`   S3 buckets      : ${s3.value.length} finding(s)`);
    console.log(`   RDS instances   : ${rds.value.length} finding(s)`);
    console.log(`   EC2 instances   : ${contexts.length} analysed for IAM relationships`);

    // ---- 2. Relate -------------------------------------------------------
    if (contexts.length > 0) {
        console.log("\n2️⃣  IAM relationship map:");
        for (const c of contexts) {
            const flags = [
                c.isPublic ? "PUBLIC" : "private",
                c.hasAdminIamPolicy ? "ADMIN-ROLE"
                    : c.hasWildcardIamPolicy ? "WILDCARD-ROLE" : "scoped-role",
                c.sensitive ? "SENSITIVE" : null,
                c.partial ? "PARTIAL-READ" : null
            ].filter(Boolean).join(" | ");
            console.log(`   ${c.instanceId} [${flags}] role=${c.roleName ?? "none"} sgs=${c.securityGroupIds.join(",")}`);
        }
    }

    const attackPaths = buildAttackPathFindings(contexts);
    if (attackPaths.length > 0) {
        console.log(`\n   🔗 ${attackPaths.length} ATTACK PATH(S) found from relationships alone:`);
        for (const ap of attackPaths) console.log(`      ⚠️  ${ap.description}`);
    }

    // ---- 3. Score --------------------------------------------------------
    const allFindings = scoreAll([...rawFindings, ...attackPaths], contexts);

    console.log(`\n3️⃣  Scored ${allFindings.length} finding(s):`);
    if (allFindings.length === 0) {
        console.log("   ✅ No security issues found. Your account looks clean!");
    }

    const high = allFindings.filter(f => f.severity === "HIGH");
    const low = allFindings.filter(f => f.severity !== "HIGH");

    for (const f of [...high, ...low]) {
        console.log(`\n   [${f.severity}] score ${f.blastRadiusScore} — ${f.type} on ${f.resourceId}`);
        console.log(`      ${f.description}`);
        if (f.riskFactors.length > 0) console.log(`      Why: ${f.riskFactors.join("; ")}`);
        if (f.relatedInstanceIds.length > 0) {
            console.log(`      Instances: ${f.relatedInstanceIds.join(", ")}`);
        }
        console.log(`      Auto-remediable: ${f.autoRemediable}${f.escalate ? " (ESCALATED to human)" : ""}`);
    }

    // ---- 4. Preview remediation (always dry run) -------------------------
    console.log(`\n4️⃣  Remediation preview (DRY RUN — nothing will be changed):`);
    if (!iam.ok) {
        console.log("   🛑 IAM scan failed, so the deployed Lambda would suppress remediation");
        console.log("      entirely for this run (fail closed — an unscored finding looks LOW).");
    }

    let previewed = 0;
    for (const finding of allFindings) {
        const decision = checkWhitelist(finding);
        if (!decision.allowed) {
            // Only worth printing for findings that were candidates at all.
            if (finding.type === "OPEN_PORT") {
                console.log(`   ⏭️  ${finding.resourceId}:${finding.port} — ${decision.reason}`);
            }
            continue;
        }

        const result = await remediateSG(finding, { dryRun: true });
        previewed++;
        console.log(`   🧪 ${finding.resourceId}:${finding.port} from ${finding.cidr} — ` +
            `${result.wouldRemediate ? "WOULD be revoked" : `not revoked (${result.reason ?? result.error})`}`);
    }
    if (previewed === 0) console.log("   (nothing eligible for auto-remediation)");

    // ---- 5. Persist ------------------------------------------------------
    if (allFindings.length > 0) {
        console.log(`\n5️⃣  Saving to DynamoDB (${config.dynamodbTableName})...`);
        let saved = 0;
        for (const finding of allFindings) {
            try {
                const result = await save(finding);
                console.log(`   ✅ ${result.findingId} (${result.status})`);
                saved++;
            } catch (error) {
                console.error(`   ❌ ${finding.findingId}: ${error.message}`);
            }
        }
        console.log(`   Saved ${saved}/${allFindings.length}`);

        const stored = await getAll();
        const open = await getByStatus("OPEN");
        console.log(`\n   📂 ${stored.length} total in table, ${open.length} currently OPEN`);
    }

    console.log(`\n${LINE}`);
    console.log("✅ Local pipeline run complete");
    console.log(`   ${high.length} HIGH severity (would be escalated by email)`);
    console.log(`   ${low.length} LOW severity`);

    const table = config.dynamodbTableName;
    console.log("\n🧹 Clean up (optional) — delete all findings from the table:");
    console.log(`   aws dynamodb scan --table-name ${table} --projection-expression findingId --query 'Items[*].findingId.S' --output text | tr '\\t' '\\n' | while read id; do aws dynamodb delete-item --table-name ${table} --key "{\\"findingId\\":{\\"S\\":\\"$id\\"}}"; done`);
}

main().catch(error => {
    console.error("\n❌ Scan failed:", error.message);
    console.error(error.stack);
    process.exit(1);
});

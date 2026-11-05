import { scan as scanSG } from "./scanners/sgScanner.js";
import { scan as scanS3 } from "./scanners/s3Scanner.js";
import { scan as scanRDS } from "./scanners/rdsScanner.js";
import { scan as scanIamRoles } from "./scanners/iamRoleScanner.js";
import { scoreAll, buildAttackPathFindings } from "./analysis/blastRadius.js";
import { fix as remediateSG } from "./remediation/remediateSG.js";
import { save } from "./storage/findingsRepo.js";
import { publishAlert } from "./notify/alerts.js";
// import logger from "./utils/logger.js"; // When implemented

const SCANNERS = [
    { name: "securityGroups", run: scanSG },
    { name: "s3Buckets", run: scanS3 },
    { name: "rdsInstances", run: scanRDS }
];

function scannerErrorFinding(name, error, note = "") {
    return {
        findingId: `scanner#${name}#SCANNER_ERROR`,
        resourceType: "scanner",
        type: "SCANNER_ERROR",
        resourceId: name,
        autoRemediable: false,
        errorName: error?.name,
        errorMessage: error?.message ?? String(error),
        description: `Scanner "${name}" failed to complete: ${error?.message ?? error}. ` +
            `Resources it covers were NOT checked in this run.${note}`
    };
}

async function runScanner({ name, run }) {
    try {
        const findings = await run();
        return { name, ok: true, findings };
    } catch (error) {
        console.error(`❌ Scanner "${name}" failed:`, error);
        return { name, ok: false, findings: [scannerErrorFinding(name, error)] };
    }
}

async function runContextScanner() {
    try {
        const contexts = await scanIamRoles();
        return { ok: true, contexts, findings: [] };
    } catch (error) {
        console.error("❌ IAM role scanner failed:", error);
        return {
            ok: false,
            contexts: [],
            findings: [scannerErrorFinding("iamRoles", error,
                " Remediation is suppressed for this run because risk cannot be scored.")]
        };
    }
}

export const handler = async (event) => {
    console.log("🚀 ChainBreak Lambda invoked at:", new Date().toISOString());

    // ---- 1 + 2. Observe and relate, all in parallel ----------------------
    const [settled, contextResult] = await Promise.all([
        Promise.allSettled(SCANNERS.map(runScanner)),
        runContextScanner()
    ]);

    const results = settled.map((outcome, index) => {
        if (outcome.status === "fulfilled") return outcome.value;

        const name = SCANNERS[index].name;
        console.error(`❌ Scanner "${name}" rejected unexpectedly:`, outcome.reason);
        return { name, ok: false, findings: [scannerErrorFinding(name, outcome.reason)] };
    });

    const failedScanners = results.filter(r => !r.ok).map(r => r.name);
    if (!contextResult.ok) failedScanners.push("iamRoles");

    const contexts = contextResult.contexts;

    // ---- 3. Score, including the relationships as findings of their own ---
    const rawFindings = [
        ...results.flatMap(r => r.findings),
        ...contextResult.findings,
        // PHASE 8: the combination is itself a finding, even when no single
        // resource looks misconfigured.
        ...buildAttackPathFindings(contexts)
    ];

    const allFindings = scoreAll(rawFindings, contexts);

    const highSeverity = allFindings.filter(f => f.severity === "HIGH");
    console.log(`📊 Found ${allFindings.length} findings (${highSeverity.length} HIGH)`);
    console.log(`🔗 Built IAM context for ${contexts.length} EC2 instance(s)`);
    if (failedScanners.length > 0) {
        console.warn(`⚠️ ${failedScanners.length} scanner(s) failed: ${failedScanners.join(", ")}`);
    }

    const remediationSafe = contextResult.ok;
    if (!remediationSafe) {
        console.warn("🛑 Remediation suppressed: IAM context incomplete, cannot score risk");
    }

    const remediationResults = [];
    const processedFindings = [];

    for (const finding of allFindings) {
        if (!remediationSafe || finding.autoRemediable !== true) {
            processedFindings.push(finding);
            continue;
        }

        const outcome = await remediateSG(finding);
        remediationResults.push({ findingId: finding.findingId, ...outcome });

        processedFindings.push({
            ...finding,
            // findingsRepo turns `remediated` into status REMEDIATED vs OPEN.
            remediated: outcome.remediated === true,
            remediatedAt: outcome.timestamp ?? null,
            remediationDryRun: outcome.dryRun === true,
            remediationSkipped: outcome.skipped === true,
            remediationNote: outcome.reason ?? outcome.error ?? null
        });
    }

    const remediatedCount = remediationResults.filter(r => r.remediated).length;
    const wouldRemediateCount = remediationResults.filter(r => r.wouldRemediate).length;

    if (remediatedCount > 0) console.log(`🔧 Auto-remediated ${remediatedCount} finding(s)`);
    if (wouldRemediateCount > 0) {
        console.log(`🧪 Dry run: would have remediated ${wouldRemediateCount} finding(s)`);
    }

    // ---- 6. Record everything, fixed or not -------------------------------
    const savedFindings = [];
    const saveErrors = [];

    for (const finding of processedFindings) {
        try {
            savedFindings.push(await save(finding));
        } catch (error) {
            console.error(`❌ Failed to save ${finding.findingId}:`, error.message);
            saveErrors.push({ findingId: finding.findingId, error: error.message });
        }
    }

    // ---- 7. Escalate what is still open -----------------------------------
    const openFindings = savedFindings.filter(f => f.status === "OPEN");
    console.log(`🔍 ${openFindings.length} finding(s) still OPEN`);

    let alertError = null;
    if (openFindings.length > 0) {
        try {
            await publishAlert(openFindings);
            console.log(`📧 Alert sent for ${openFindings.length} findings`);
        } catch (error) {
            console.error("❌ Failed to publish alert:", error.message);
            alertError = error.message;
        }
    }

    const degraded = failedScanners.length > 0 || saveErrors.length > 0 || alertError !== null;

    return {
        statusCode: degraded ? 207 : 200,
        body: JSON.stringify({
            message: degraded ? "Scan completed with errors" : "Scan completed successfully",
            totalFindings: allFindings.length,
            highSeverity: highSeverity.length,
            attackPaths: allFindings.filter(f => f.type === "ATTACK_PATH").length,
            instancesAnalysed: contexts.length,
            savedFindings: savedFindings.length,
            openFindings: openFindings.length,
            remediated: remediatedCount,
            wouldRemediate: wouldRemediateCount,
            remediationSuppressed: !remediationSafe,
            failedScanners,
            saveErrors,
            alertError
        })
    };
};

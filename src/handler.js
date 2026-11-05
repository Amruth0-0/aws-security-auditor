import { scan as scanSG } from "./scanners/sgScanner.js";
import { scan as scanS3 } from "./scanners/s3Scanner.js";
import { scan as scanRDS } from "./scanners/rdsScanner.js";
import { save } from "./storage/findingsRepo.js";
import { publishAlert } from "./notify/alerts.js";
// import logger from "./utils/logger.js"; // When implemented

const SCANNERS = [
    { name: "securityGroups", run: scanSG },
    { name: "s3Buckets", run: scanS3 },
    { name: "rdsInstances", run: scanRDS }
];

async function runScanner({ name, run }) {
    try {
        const findings = await run();
        return { name, ok: true, findings };
    } catch (error) {
        console.error(`❌ Scanner "${name}" failed:`, error);

        return {
            name,
            ok: false,
            findings: [{
                findingId: `scanner#${name}#SCANNER_ERROR`,
                resourceType: "scanner",
                type: "SCANNER_ERROR",
                resourceId: name,
                autoRemediable: false,
                errorName: error.name,
                errorMessage: error.message,
                description: `Scanner "${name}" failed to complete: ${error.message}. ` +
                    `Resources it covers were NOT checked in this run.`
            }]
        };
    }
}

export const handler = async (event) => {
    console.log("🚀 ChainBreak Lambda invoked at:", new Date().toISOString());

    const settled = await Promise.allSettled(SCANNERS.map(runScanner));

    const results = settled.map((outcome, index) => {
        if (outcome.status === "fulfilled") return outcome.value;

        const name = SCANNERS[index].name;
        console.error(`❌ Scanner "${name}" rejected unexpectedly:`, outcome.reason);
        return {
            name,
            ok: false,
            findings: [{
                findingId: `scanner#${name}#SCANNER_ERROR`,
                resourceType: "scanner",
                type: "SCANNER_ERROR",
                resourceId: name,
                autoRemediable: false,
                errorMessage: String(outcome.reason?.message || outcome.reason),
                description: `Scanner "${name}" rejected unexpectedly.`
            }]
        };
    });

    const failedScanners = results.filter(r => !r.ok).map(r => r.name);
    const allFindings = results.flatMap(r => r.findings);

    console.log(`📊 Found ${allFindings.length} total findings`);
    if (failedScanners.length > 0) {
        console.warn(`⚠️ ${failedScanners.length} scanner(s) failed: ${failedScanners.join(", ")}`);
    }
    const savedFindings = [];
    const saveErrors = [];

    for (const finding of allFindings) {
        try {
            savedFindings.push(await save(finding));
        } catch (error) {
            console.error(`❌ Failed to save ${finding.findingId}:`, error.message);
            saveErrors.push({ findingId: finding.findingId, error: error.message });
        }
    }

    const openFindings = savedFindings.filter(f => f.status === "OPEN");
    console.log(`🔍 Found ${openFindings.length} OPEN findings`);

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
            message: degraded
                ? "Scan completed with errors"
                : "Scan completed successfully",
            totalFindings: allFindings.length,
            savedFindings: savedFindings.length,
            openFindings: openFindings.length,
            failedScanners,
            saveErrors,
            alertError
        })
    };
};

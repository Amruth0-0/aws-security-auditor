import { scan as scanSG } from "./scanners/sgScanner.js";
import { scan as scanS3 } from "./scanners/s3Scanner.js";
import { scan as scanRDS } from "./scanners/rdsScanner.js";
import { save, getByStatus } from "./storage/findingsRepo.js";
import { publishAlert } from "./notify/alerts.js";
// import logger from "./utils/logger.js"; // When implemented

export const handler = async (event) => {
    console.log("🚀 ChainBreak Lambda invoked at:", new Date().toISOString());

    try {
        const [sgFindings, s3Findings, rdsFindings] = await Promise.all([
            scanSG(),
            scanS3(),
            scanRDS()
        ]);

        const allFindings = [...sgFindings, ...s3Findings, ...rdsFindings];
        console.log(`📊 Found ${allFindings.length} total findings`);

        for (const finding of allFindings) {
            await save(finding);
        }

        const openFindings = await getByStatus("OPEN");
        console.log(`🔍 Found ${openFindings.length} OPEN findings`);

        if (openFindings.length > 0) {
            await publishAlert(openFindings);
            console.log(`📧 Alert sent for ${openFindings.length} findings`);
        }

        return {
            statusCode: 200,
            body: JSON.stringify({
                message: "Scan completed successfully",
                totalFindings: allFindings.length,
                openFindings: openFindings.length
            })
        };

    } catch (error) {
        console.error("❌ Lambda execution failed:", error);
        throw error;
    }
};
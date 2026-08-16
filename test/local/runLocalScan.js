import { scan as scanSG } from "../../src/scanners/sgScanner.js";
import { scan as scanS3 } from "../../src/scanners/s3Scanner.js";
import { scan as scanRDS } from "../../src/scanners/rdsScanner.js";

/**
 * Run all scanners locally against your real AWS account.
 * This is the development loop — no Lambda deployment needed!
*/

async function main() {
  console.log("🔍 ChainBreak - Local Scanner Test");
  console.log("📅", new Date().toISOString());
  console.log("=".repeat(60));

  try {
    const [sgFindings, s3Findings, rdsFindings] = await Promise.all([
      scanSG(),
      scanS3(),
      scanRDS()
    ]);

    const allFindings = [...sgFindings, ...s3Findings, ...rdsFindings];
    
    console.log(`\n📊 SCAN COMPLETE: Found ${allFindings.length} issues\n`);
    console.log("-".repeat(60));

    if (allFindings.length === 0) {
      console.log("✅ No security issues found. Your account looks clean!");
    } else {
      const byType = allFindings.reduce((acc, f) => {
        acc[f.type] = (acc[f.type] || 0) + 1;
        return acc;
      }, {});
      
      console.log("📋 Issues by type:");
      for (const [type, count] of Object.entries(byType)) {
        console.log(`   - ${type}: ${count}`);
      }
      
      console.log("\n📋 Detailed findings:");
      for (const finding of allFindings) {
        console.log(`\n   ⚠️ [${finding.type}] ${finding.description}`);
        console.log(`      Resource: ${finding.resourceId}`);
        console.log(`      Auto-remediable: ${finding.autoRemediable}`);
        if (finding.port) console.log(`      Port: ${finding.port}`);
        if (finding.reason) console.log(`      Reason: ${finding.reason}`);
      }
    }

    console.log("\n" + "=".repeat(60));
    console.log("✅ Local scan complete!");
    console.log("   (No data was written to DynamoDB or sent via SNS yet)");
    
  } catch (error) {
    console.error("\n❌ Scan failed:", error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

main();
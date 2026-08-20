process.env.FINDINGS_TABLE_NAME = "chainbreak-findings";

import { scan as scanSG } from "../../src/scanners/sgScanner.js";
import { scan as scanS3 } from "../../src/scanners/s3Scanner.js";
import { scan as scanRDS } from "../../src/scanners/rdsScanner.js";
import { save, getAll, getByStatus } from "../../src/storage/findingsRepo.js";

/**
 * Run all scanners locally against your real AWS account.
 * This is the development loop — no Lambda deployment needed!
 */

async function main() {
  console.log("🔍 ChainBreak - Local Scanner Test with Storage"); // CHANGED: Updated title
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


      console.log("\n💾 Saving findings to DynamoDB...");
      let savedCount = 0;
      for (const finding of allFindings) {
        try {
          const saved = await save(finding);
          console.log(`   ✅ Saved: ${saved.findingId} (${saved.status})`);
          savedCount++;
        } catch (error) {
          console.error(`   ❌ Failed to save ${finding.resourceId}: ${error.message}`);
        }
      }
      console.log(`   ✅ Successfully saved ${savedCount}/${allFindings.length} findings`);

      console.log("\n📂 Retrieving all findings from DynamoDB...");
      const storedFindings = await getAll();
      console.log(`   ✅ Found ${storedFindings.length} total findings in table`);

      console.log("\n🔍 Querying OPEN findings via GSI...");
      const openFindings = await getByStatus("OPEN");
      console.log(`   ✅ Found ${openFindings.length} OPEN findings requiring attention`);
      
      if (openFindings.length > 0) {
        console.log("   ⚠️ Findings requiring remediation:");
        openFindings.forEach(f => {
          console.log(`   - ${f.findingId} (${f.type})`);
        });
      } else {
        console.log("   ✅ No OPEN findings - everything is remediated or clean!");
      }
    }

    console.log("\n" + "=".repeat(60));
    console.log("✅ Local scan with storage complete!"); 
    console.log(`   Findings saved to: chainbreak-findings`); 

    
    console.log("\n🧹 Clean up (optional):");
    console.log("   To delete all findings from the table:");
    console.log("   aws dynamodb scan --table-name chainbreak-findings --projection-expression findingId --query 'Items[*].findingId.S' --output text | tr '\\t' '\\n' | while read id; do aws dynamodb delete-item --table-name chainbreak-findings --key \"{\\\"findingId\\\":{\\\"S\\\":\\\"$id\\\"}}\"; done");

  } catch (error) {
    console.error("\n❌ Scan failed:", error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

main();
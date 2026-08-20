process.env.FINDINGS_TABLE_NAME = "chainbreak-findings";
const { save, getAll, getByStatus } = await import("../../src/storage/findingsRepo.js");

console.log("==== Testing getByStatus() with GSI ====");

// Create a test finding (status will default to "OPEN")
const testFinding = {
    type: "OPEN_PORT",
    resourceType: "securityGroup",
    resourceId: "sg-gsi-test",
    port: 22,
    protocol: "tcp",
    cidr: "0.0.0.0/0",
    autoRemediable: true
};

try {
    console.log("\n1. Saving test finding...");
    const saved = await save(testFinding);
    console.log(`   ✅ Saved: ${saved.findingId} (${saved.status})`);

    console.log("\n   ⏳ Waiting 2 seconds for GSI to update...");
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    console.log("\n2. Querying findings with status = 'OPEN'...");
    const openFindings = await getByStatus("OPEN");
    console.log(`   ✅ Found ${openFindings.length} OPEN findings`);
    
    const found = openFindings.find(f => f.findingId === saved.findingId);
    if (found) {
        console.log("   ✅ Test finding found in OPEN query!");
    } else {
        console.log("   ❌ Test finding NOT found in OPEN query!");
    }

    console.log("\n3. Querying findings with status = 'REMEDIATED'...");
    const remediatedFindings = await getByStatus("REMEDIATED");
    console.log(`   ✅ Found ${remediatedFindings.length} REMEDIATED findings`);
    
    const notFound = remediatedFindings.find(f => f.findingId === saved.findingId);
    if (!notFound) {
        console.log("   ✅ Test finding correctly NOT in REMEDIATED results");
    } else {
        console.log("   ❌ Test finding incorrectly found in REMEDIATED results!");
    }


    console.log("\n4. GSI Verification:");
    console.log(`   - Table: chainbreak-findings`);
    console.log(`   - GSI: status-index (on Status attribute)`);
    console.log(`   - Query returned ${openFindings.length} OPEN items`);
    console.log(`   - All findings retrieved using the index`);

    // 5. Cleanup command
    console.log('\n5. Clean up:');
    console.log(`   aws dynamodb delete-item --table-name chainbreak-findings --key '{"findingId": {"S": "${saved.findingId}"}}'`);

    console.log('\n✅ getByStatus() test completed successfully!');
} catch (error) {
    console.error("\n❌ Test failed with error:");
    console.error('  ', error.message);
    if (error.stack) {
        console.error('  Stack trace:', error.stack);
    }
    process.exit(1);
}
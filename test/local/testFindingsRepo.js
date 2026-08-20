process.env.FINDINGS_TABLE_NAME = "chainbreak-findings"
const { save, getAll, getByStatus} = await import("../../src/storage/findingsRepo.js");

// Create a fake finding object (simulating what sgScanner would produce)
const fakeFinding = {
    type: "OPEN_PORT",
    resourceType: 'securityGroup',
    resourceId: 'sg-test123',
    port: 22,
    protocol: 'tcp',
    cidr: '0.0.0.0/0',
    autoRemediable: true
}

console.log("==== Testing findingsRepo ====")
console.log("Create fake finding", JSON.stringify(fakeFinding, null, 2));

try{
    console.log("\n1, Saving finding....");
    const saved = await save(fakeFinding);
    console.log("✅Saved Successfully");
    console.log("Generating findingsId ", saved.findingId);
    console.log('Status:', saved.status)
    console.log("LastSeenAt: ", saved.lastSeenAt)

    console.log("\n2. Retrieving all findings...")
    const allFindings = await getAll();
    console.log(`✅ Found ${allFindings.length} total findings`);

    const testFinding = allFindings.find(f => f.findingId === saved.findingId);
    if(testFinding){
         console.log('   ✅ Test finding found in table!');
         console.log('   Finding details:', JSON.stringify(testFinding, null, 2));
    }else{
        console.log('   ❌ Test finding NOT found in table!');
        console.log('   All findings:', JSON.stringify(allFindings, null, 2));
    }  

    console.log('\n3. Clean up (optional): ');
    console.log("To Delete the finding manually, run: ")
    console.log(` aws dynamodb delete-item --table-name chainbreak-findings --key '{"findingId": {"S": "${saved.findingId}"}}'`);

    console.log('\n✅ Test completed successfully!');
}catch(error){
    console.error("\n❌ Test failed with error");
    console.error('  ', error.message);
    if(error.stack){
        console.error('  Stack trace:', error.stack);
    }
    process.exit(1);
}
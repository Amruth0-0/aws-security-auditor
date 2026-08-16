import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";


// Scans all RDS instances for unencrypted storage.

export async function scan() {
  const client = new RDSClient({ 
    region: process.env.AWS_REGION || "us-east-1" 
  });
  
  const findings = [];

  try {
    const command = new DescribeDBInstancesCommand({});
    const response = await client.send(command);
   
    for (const instance of response.DBInstances || []) {
      if (instance.StorageEncrypted === false) {
        findings.push({
          type: "UNENCRYPTED_RDS",
          resourceId: instance.DBInstanceIdentifier,
          engine: instance.Engine,
          engineVersion: instance.EngineVersion,
          instanceClass: instance.DBInstanceClass,
          storageType: instance.StorageType,
          allocatedStorage: instance.AllocatedStorage,
          autoRemediable: false,  
          description: `RDS instance ${instance.DBInstanceIdentifier} has unencrypted storage (StorageEncrypted: false)`
        });
      }
    }
    
    return findings;
  } catch (error) {
    console.error("Error scanning RDS instances:", error.message);
    throw error;
  }
}
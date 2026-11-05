import { RDSClient, paginateDescribeDBInstances } from "@aws-sdk/client-rds";
import config from "../config/env.js";


function buildFindingId(dbInstanceIdentifier) {
  return `rdsInstance#${dbInstanceIdentifier}#UNENCRYPTED_RDS`;
}

export async function scan() {
  const client = new RDSClient({ region: config.region });

  const findings = [];

  try {
    const pages = paginateDescribeDBInstances({ client }, {});

    for await (const page of pages) {
      for (const instance of page.DBInstances || []) {
        if (instance.StorageEncrypted === false) {
          findings.push({
            findingId: buildFindingId(instance.DBInstanceIdentifier),
            resourceType: "rdsInstance",
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
    }

    return findings;
  } catch (error) {
    console.error("Error scanning RDS instances:", error.message);
    throw error;
  }
}

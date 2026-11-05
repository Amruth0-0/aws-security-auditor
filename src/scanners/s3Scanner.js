import { S3Client, paginateListBuckets, GetPublicAccessBlockCommand } from "@aws-sdk/client-s3";
import config from "../config/env.js";

function buildFindingId(bucketName) {
  return `s3Bucket#${bucketName}#PUBLIC_BUCKET`;
}

export async function scan() {
  const client = new S3Client({ region: config.region });

  const findings = [];

  try {
    const pages = paginateListBuckets({ client }, {});

    for await (const page of pages) {
      for (const bucket of page.Buckets || []) {
        const bucketName = bucket.Name;
        let isPublic = false;
        let reason = "";

        try {
          const publicAccessCommand = new GetPublicAccessBlockCommand({
            Bucket: bucketName
          });

          const response = await client.send(publicAccessCommand);
          const blockConfig = response.PublicAccessBlockConfiguration || {};

          if (blockConfig.BlockPublicAcls === false) {
            isPublic = true;
            reason = "BlockPublicAcls is false";
          } else if (blockConfig.BlockPublicPolicy === false) {
            isPublic = true;
            reason = "BlockPublicPolicy is false";
          } else if (blockConfig.IgnorePublicAcls === false) {
            isPublic = true;
            reason = "IgnorePublicAcls is false";
          } else if (blockConfig.RestrictPublicBuckets === false) {
            isPublic = true;
            reason = "RestrictPublicBuckets is false";
          }
        } catch (error) {
          if (error.name === "NoSuchPublicAccessBlockConfiguration") {
            isPublic = true;
            reason = "No public access block configuration exists";
          } else {
            console.warn(`Could not check public access for bucket ${bucketName}:`, error.message);
          }
        }

        if (isPublic) {
          findings.push({
            findingId: buildFindingId(bucketName),
            resourceType: "s3Bucket",
            type: "PUBLIC_BUCKET",
            resourceId: bucketName,
            autoRemediable: false,
            reason: reason,
            description: `S3 bucket ${bucketName} is publicly accessible: ${reason}`
          });
        }
      }
    }

    return findings;
  } catch (error) {
    console.error("Error scanning S3 buckets: ", error.message);
    throw error;
  }
}

import { S3Client, ListBucketsCommand, GetPublicAccessBlockCommand } from "@aws-sdk/client-s3";

// Scans all S3 buckets for public access vulnerabilities.

export async function scan() {
  const client = new S3Client({
    region: process.env.AWS_REGION || "us-east-1"
  });

  const findings = [];

  try {
    const listCommand = new ListBucketsCommand({});
    const { Buckets = [] } = await client.send(listCommand);

    for (const bucket of Buckets) {
      const bucketName = bucket.Name;
      let isPublic = false;
      let reason = "";

      try {
        const publicAccessCommand = new GetPublicAccessBlockCommand({
          Bucket: bucketName
        });

        const response = await client.send(publicAccessCommand);
        const config = response.PublicAccessBlockConfiguration || {};

        if (config.BlockPublicAcls === false) {
          isPublic = true;
          reason = "BlockPublicAcls is false";
        } else if (config.BlockPublicPolicy === false) {
          isPublic = true;
          reason = "BlockPublicPolicy is false";
        } else if (config.IgnorePublicAcls === false) {
          isPublic = true;
          reason = "IgnorePublicAcls is false";
        } else if (config.RestrictPublicBuckets === false) {
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
          type: "PUBLIC_BUCKET",
          resourceId: bucketName,
          autoRemediable: false,
          reason: reason,
          description: `S3 bucket ${bucketName} is publicly accessible: ${reason}`
        });
      }
    }

    return findings;
  } catch (error) {
    console.error("Error scanning S3 buckets: ", error.message);
    throw error;
  }
}
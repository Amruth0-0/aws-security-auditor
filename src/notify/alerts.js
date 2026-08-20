import { SNSClient, PublishCommand } from "@aws-sdk/client-sns";
import config from "../config/env.js";

const client = new SNSClient({});

export async function publishAlert(findings) {
    if (!findings || findings.length === 0) {
        console.log("No findings to alert");
        return;
    }

    const messageLines = [
        `ChainBreak Alert`,
        `================`,
        `Found ${findings.length} OPEN security findings that require attention:`,
        ``
    ];

    for (const finding of findings) {
        messageLines.push(`- ${finding.findingId}`);
        messageLines.push(`  Type: ${finding.type}`);
        messageLines.push(`  Resource: ${finding.resourceId}`);
        if (finding.port) messageLines.push(`  Port: ${finding.port}`);
        if (finding.cidr) messageLines.push(`  CIDR: ${finding.cidr}`);
        messageLines.push(`  Auto-remediable: ${finding.autoRemediable}`);
        messageLines.push(`  Status: ${finding.status}`);
        messageLines.push(`  Last seen: ${finding.lastSeenAt}`);
        messageLines.push(`---`);
    }

    const message = messageLines.join('\n');
    const subject = `ChainBreak: ${findings.length} open security findings`;

    console.log(`📧 Publishing alert to SNS: ${subject}`);

    const command = new PublishCommand({
        TopicArn: config.snsTopicArn,
        Subject: subject,
        Message: message
    });

    try {
        await client.send(command);
        console.log(`✅ Alert published successfully`);
    } catch (error) {
        console.error(`❌ Failed to publish alert: ${error.message}`);
        throw error;
    }
}
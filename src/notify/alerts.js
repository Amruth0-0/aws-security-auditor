import { SNSClient, PublishCommand } from "@aws-sdk/client-sns";
import config from "../config/env.js";

const client = new SNSClient({});
const SEPARATOR = "=".repeat(60);

function formatFinding(finding, index) {
    const lines = [];

    lines.push(`${index}. [${finding.severity ?? "?"}] ${finding.type} — ${finding.resourceId}`);
    if (finding.description) lines.push(`   ${finding.description}`);

    if (typeof finding.blastRadiusScore === "number") {
        lines.push(`   Blast radius score: ${finding.blastRadiusScore}`);
    }

    // The "why" behind the score — the part that makes this actionable.
    if (finding.riskFactors?.length > 0) {
        lines.push(`   Why: ${finding.riskFactors.join("; ")}`);
    }

    if (finding.relatedInstanceIds?.length > 0) {
        lines.push(`   Affected instances: ${finding.relatedInstanceIds.join(", ")}`);
    }

    if (finding.roleName) lines.push(`   IAM role: ${finding.roleName}`);

    for (const policy of finding.offendingPolicies ?? []) {
        for (const statement of policy.statements ?? []) {
            lines.push(
                `   Policy ${policy.policyName}: Action ${JSON.stringify(statement.actions)} ` +
                `on Resource ${JSON.stringify(statement.resources)}`
            );
        }
    }

    if (finding.port) lines.push(`   Port: ${finding.port}/${finding.ipProtocol ?? "?"}`);
    if (finding.cidr) lines.push(`   Exposed to: ${finding.cidr}`);

    if (finding.escalate) {
        lines.push(`   Action: ESCALATED — not auto-fixed, needs a human decision`);
    } else if (finding.remediationDryRun) {
        lines.push(`   Action: would auto-fix (dry run — remediation is disabled)`);
    } else if (finding.remediationSkipped) {
        lines.push(`   Action: not auto-fixed — ${finding.remediationNote}`);
    } else if (finding.autoRemediable) {
        lines.push(`   Action: eligible for auto-remediation`);
    }

    lines.push(`   Finding ID: ${finding.findingId}`);
    lines.push(`   Last seen: ${finding.lastSeenAt}`);

    return lines;
}

export async function publishAlert(findings) {
    if (!findings || findings.length === 0) {
        console.log("No findings to alert");
        return;
    }

    const escalated = findings.filter(f => f.severity === "HIGH");
    const other = findings.filter(f => f.severity !== "HIGH");

    const messageLines = [
        "ChainBreak Security Alert",
        SEPARATOR,
        `${findings.length} finding(s) require attention.`,
        `${escalated.length} escalated to a human, ${other.length} other open finding(s).`,
        ""
    ];

    if (escalated.length > 0) {
        messageLines.push(
            "NEEDS A HUMAN DECISION",
            "-".repeat(60),
            "These were deliberately NOT auto-remediated. Their blast radius is",
            "large enough that an automatic fix could break something real.",
            ""
        );
        escalated.forEach((finding, i) => {
            messageLines.push(...formatFinding(finding, i + 1), "");
        });
    }

    if (other.length > 0) {
        messageLines.push("OTHER OPEN FINDINGS", "-".repeat(60), "");
        other.forEach((finding, i) => {
            messageLines.push(...formatFinding(finding, i + 1), "");
        });
    }

    messageLines.push(
        SEPARATOR,
        "Auto-remediated findings are recorded in DynamoDB with status REMEDIATED",
        "and are intentionally not listed here."
    );

    const subject = escalated.length > 0
        ? `ChainBreak: ${escalated.length} HIGH severity finding(s) need review`
        : `ChainBreak: ${findings.length} open security finding(s)`;

    console.log(`📧 Publishing alert to SNS: ${subject}`);

    const command = new PublishCommand({
        TopicArn: config.snsTopicArn,
        // SNS caps Subject at 100 characters and rejects anything longer.
        Subject: subject.slice(0, 99),
        Message: messageLines.join("\n")
    });

    try {
        await client.send(command);
        console.log(`✅ Alert published successfully`);
    } catch (error) {
        console.error(`❌ Failed to publish alert: ${error.message}`);
        throw error;
    }
}

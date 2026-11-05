import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand, paginateScan, QueryCommand } from "@aws-sdk/lib-dynamodb";
import config from "../config/env.js";

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);

export async function save(finding) {
    if (!finding?.findingId) {
        throw new Error(
            "Finding is missing findingId — the scanner that produced it must set one " +
            "(see the canonical shapes in src/storage/findingsRepo.js)"
        );
    }

    const item = {
        ...finding,
        status: finding.remediated === true ? "REMEDIATED" : "OPEN",
        lastSeenAt: new Date().toISOString()
    };

    const command = new PutCommand({ TableName: config.dynamodbTableName, Item: item });

    try {
        await docClient.send(command);
        return item;
    } catch (error) {
        throw new Error(`Failed to save finding ${item.findingId}: ${error.message}`);
    }
}

export async function getAll() {
    try {
        const items = [];
        const pages = paginateScan(
            { client: docClient },
            { TableName: config.dynamodbTableName }
        );

        for await (const page of pages) {
            items.push(...(page.Items || []));
        }

        return items;
    } catch (error) {
        throw new Error(`Failed to scan findings: ${error.message}`);
    }
}

export async function getByStatus(status) {
    try {
        const command = new QueryCommand({
            TableName: config.dynamodbTableName,
            IndexName: 'status-index',
            KeyConditionExpression: '#status = :status',
            ExpressionAttributeNames: {
                '#status': 'status'
            },
            ExpressionAttributeValues: {
                ':status': status
            }
        });

        const response = await docClient.send(command);
        return response.Items || [];
    } catch (error) {
        throw new Error(`Failed to query findings by status ${status}: ${error.message}`);
    }
}

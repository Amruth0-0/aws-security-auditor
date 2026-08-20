import{DynamoDBClient} from "@aws-sdk/client-dynamodb"
import {DynamoDBDocumentClient, PutCommand, ScanCommand, QueryCommand} from "@aws-sdk/lib-dynamodb";
import config from "../config/env.js"

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client)

function generateFindingId(finding){
    if(finding.findingId){
        return finding.findingId
    }

    const resourceType = finding.resourceType || 'unknown';
    const resourceId = finding.resourceId || 'unknown';
    const findingType = finding.type || 'unknown';

    return `${resourceType}-${resourceId}#${findingType}`;
}

export async function save(finding) {
    finding.findingId = generateFindingId(finding)

    finding.status = finding.remediated === true? "REMEDIATED" : "OPEN"
    
    finding.lastSeenAt = new Date().toISOString();

    const command = new PutCommand({ TableName: config.dynamodbTableName, Item: finding});

    try{
        await docClient.send(command);
        return finding
    }catch(error){
        throw new Error(`Failed to save finding ${finding.findingId}: ${error.message}`);
    }
}

export async function getAll(){
    try{
        const command = new ScanCommand({ TableName: config.dynamodbTableName});
        const response = await docClient.send(command)
         return response.Items  || [];
    }catch(error){
        throw new Error(`Failed to scan findings: ${error.message}`);
    }
}

export async function getByStatus(status) {
    try{
        const command = new QueryCommand({
            TableName: config.dynamodbTableName,
            IndexName : 'status-index',
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
    }catch(error){
        throw new Error(`Failed to query findings by status ${status}: ${error.message}`);
    }
}
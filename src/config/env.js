const REQUIRED = {
    FINDINGS_TABLE_NAME: process.env.FINDINGS_TABLE_NAME,
    SNS_TOPIC_ARN: process.env.SNS_TOPIC_ARN
}

Object.entries(REQUIRED).forEach(([key, value]) => {
    if (!value) {
        throw new Error(`Missing required environment variable: ${key}`);
    }
});

const EXCLUDED_SG_IDS = process.env.EXCLUDED_SG_IDS
    ? process.env.EXCLUDED_SG_IDS.split(',').map(s => s.trim()) : [];

const REMEDIATION_WHITELIST = process.env.REMEDIATION_WHITELIST
    ? JSON.parse(process.env.REMEDIATION_WHITELIST)
    : {};

export default Object.freeze({
    region: process.env.AWS_REGION || 'us-east-1',
    dynamodbTableName: REQUIRED.FINDINGS_TABLE_NAME,
    excludedSecurityGroupIds: EXCLUDED_SG_IDS,
    remediationWhitelist: REMEDIATION_WHITELIST,
    isProduction: process.env.NODE_ENV === 'production',
    isTest: process.env.NODE_ENV === 'test',
    snsTopicArn: REQUIRED.SNS_TOPIC_ARN,
});
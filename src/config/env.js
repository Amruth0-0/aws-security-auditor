/**
 * Centralised environment config — the ONLY place in the codebase that reads
 * process.env directly (Builder's Manual, src/config/env.js).
 */

function required(name) {
    const value = process.env[name];
    if (!value) {
        throw new Error(`Missing required environment variable: ${name}`);
    }
    return value;
}

function parseExcludedSgIds() {
    return process.env.EXCLUDED_SG_IDS
        ? process.env.EXCLUDED_SG_IDS.split(',').map(s => s.trim()).filter(Boolean)
        : [];
}

function parseRemediationWhitelist() {
    if (!process.env.REMEDIATION_WHITELIST) {
        return {};
    }
    try {
        return JSON.parse(process.env.REMEDIATION_WHITELIST);
    } catch (error) {
        throw new Error(`REMEDIATION_WHITELIST is not valid JSON: ${error.message}`);
    }
}

export default Object.freeze({
    region: process.env.AWS_REGION || 'us-east-1',

    get dynamodbTableName() {
        return required('FINDINGS_TABLE_NAME');
    },

    get snsTopicArn() {
        return required('SNS_TOPIC_ARN');
    },

    get excludedSecurityGroupIds() {
        return parseExcludedSgIds();
    },

    get remediationWhitelist() {
        return parseRemediationWhitelist();
    },

    isProduction: process.env.NODE_ENV === 'production',
    isTest: process.env.NODE_ENV === 'test',
});

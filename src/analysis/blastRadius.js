import config from "../config/env.js";

export const BASE_POINTS = {
  OPEN_PORT: 5,
  PUBLIC_BUCKET: 4,
  UNENCRYPTED_RDS: 4,
  ATTACK_PATH: 8,
  SCANNER_ERROR: 0
};
const DEFAULT_BASE_POINTS = 3;
export const POINTS = {
  PUBLICLY_REACHABLE: 4,
  WILDCARD_IAM: 3,
  ADMIN_IAM: 2,
  SENSITIVE_TAG: 2
};

export const DEFAULT_THRESHOLD = 12;

export const SEVERITY = { HIGH: "HIGH", LOW: "LOW" };
export function contextsForFinding(finding, contexts = []) {
  if (!finding) return [];

  if (finding.type === "OPEN_PORT") {
    return contexts.filter(c => (c.securityGroupIds || []).includes(finding.resourceId));
  }

  if (finding.resourceType === "ec2Instance") {
    return contexts.filter(c => c.instanceId === finding.resourceId);
  }

  return [];
}

export function worstCaseContext(contexts = []) {
  if (contexts.length === 0) return null;

  return contexts.reduce((worst, c) => ({
    isPublic: worst.isPublic || Boolean(c.isPublic),
    hasWildcardIamPolicy: worst.hasWildcardIamPolicy || Boolean(c.hasWildcardIamPolicy),
    hasAdminIamPolicy: worst.hasAdminIamPolicy || Boolean(c.hasAdminIamPolicy),
    sensitive: worst.sensitive || Boolean(c.sensitive),
    partial: worst.partial || Boolean(c.partial),
    instanceIds: [...worst.instanceIds, c.instanceId].filter(Boolean)
  }), {
    isPublic: false,
    hasWildcardIamPolicy: false,
    hasAdminIamPolicy: false,
    sensitive: false,
    partial: false,
    instanceIds: []
  });
}

export function score(finding, contexts = [], options = {}) {
  const threshold = options.threshold ?? config.severityThreshold ?? DEFAULT_THRESHOLD;

  const matched = contextsForFinding(finding, contexts);
  const worst = worstCaseContext(matched);

  const base = BASE_POINTS[finding.type] ?? DEFAULT_BASE_POINTS;
  let total = base;
  const riskFactors = [];

  if (worst?.isPublic) {
    total += POINTS.PUBLICLY_REACHABLE;
    riskFactors.push("publicly reachable (public subnet + public IP)");
  }
  if (worst?.hasWildcardIamPolicy) {
    total += POINTS.WILDCARD_IAM;
    riskFactors.push("attached IAM role grants wildcard permissions");
  }
  if (worst?.hasAdminIamPolicy) {
    total += POINTS.ADMIN_IAM;
    riskFactors.push("attached IAM role grants full administrator access");
  }
  if (worst?.sensitive) {
    total += POINTS.SENSITIVE_TAG;
    riskFactors.push("resource is tagged Sensitive");
  }

  const severity = total >= threshold ? SEVERITY.HIGH : SEVERITY.LOW;

  const autoRemediable = finding.autoRemediable === true && severity !== SEVERITY.HIGH;

  return {
    ...finding,
    severity,
    blastRadiusScore: total,
    blastRadiusBase: base,
    riskFactors,
    relatedInstanceIds: worst?.instanceIds ?? [],
    contextIncomplete: Boolean(worst?.partial),
    autoRemediable,
    escalate: severity === SEVERITY.HIGH
  };
}

export function scoreAll(findings = [], contexts = [], options = {}) {
  return findings.map(finding => score(finding, contexts, options));
}

export function buildAttackPathFindings(contexts = []) {
  return contexts
    .filter(c => c.isPublic && (c.hasWildcardIamPolicy || c.hasAdminIamPolicy))
    .map(c => {
      const privilege = c.hasAdminIamPolicy
        ? "full administrator access"
        : "wildcard permissions";

      return {
        findingId: `ec2Instance#${c.instanceId}#ATTACK_PATH`,
        resourceType: "ec2Instance",
        type: "ATTACK_PATH",
        resourceId: c.instanceId,
        instanceName: c.name,
        subnetId: c.subnetId,
        vpcId: c.vpcId,
        roleName: c.roleName,
        autoRemediable: false,
        offendingPolicies: c.offendingPolicies,
        description:
          `EC2 instance ${c.instanceId}${c.name ? ` (${c.name})` : ""} is reachable from the ` +
          `internet and its IAM role ${c.roleName} grants ${privilege}. ` +
          `Compromising this instance would hand an attacker those permissions.`
      };
    });
}

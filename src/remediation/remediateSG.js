import { EC2Client, RevokeSecurityGroupIngressCommand } from "@aws-sdk/client-ec2";
import config from "../config/env.js";

const TCP_PROTOCOLS = new Set(["tcp", "6"]);
export function checkWhitelist(finding, options = {}) {
  const whitelist = options.whitelist ?? config.remediationWhitelist ?? {};
  const excluded = options.excludedSecurityGroupIds ?? config.excludedSecurityGroupIds ?? [];

  const deny = (reason) => ({ allowed: false, reason });

  if (!finding) return deny("no finding supplied");

  // Gate 1-3: the finding must be the right kind, fixable, and not escalated.
  if (finding.type !== "OPEN_PORT") return deny(`type ${finding.type} is not remediable`);
  if (finding.autoRemediable !== true) return deny("finding is not marked auto-remediable");
  if (finding.severity === "HIGH") return deny("HIGH severity findings are escalated, never auto-fixed");

  // Gate 4: fail closed on an incomplete picture.
  if (finding.contextIncomplete === true) {
    return deny("IAM context was incomplete, so the score may under-estimate the risk");
  }

  // Gate 5: explicit operator opt-out always wins.
  if (excluded.includes(finding.resourceId)) {
    return deny(`security group ${finding.resourceId} is on the exclusion list`);
  }

  // The exact tuple must be present — without it we cannot revoke precisely.
  const { resourceId, ipProtocol, fromPort, toPort, cidr, port } = finding;
  if (!resourceId || !ipProtocol || !cidr || typeof port !== "number") {
    return deny("finding is missing the fields needed to revoke a single rule");
  }

  // Gate 6: the whitelist is FAIL-CLOSED. An empty or absent whitelist permits
  // nothing. A deployment that forgets to configure it does no damage.
  const allowedPorts = Array.isArray(whitelist.ports) ? whitelist.ports : [];
  const allowedCidrs = Array.isArray(whitelist.cidrs) ? whitelist.cidrs : [];

  if (allowedPorts.length === 0 || allowedCidrs.length === 0) {
    return deny("remediation whitelist is empty, so nothing is permitted");
  }
  if (!allowedPorts.includes(port)) return deny(`port ${port} is not whitelisted`);
  if (!allowedCidrs.includes(cidr)) return deny(`CIDR ${cidr} is not whitelisted`);

  // Gate 7: narrow, single-port TCP rules only.
  if (!TCP_PROTOCOLS.has(String(ipProtocol).toLowerCase())) {
    return deny(`protocol ${ipProtocol} is too broad to revoke automatically`);
  }
  if (fromPort !== port || toPort !== port) {
    return deny(
      `rule spans ports ${fromPort}-${toPort}; only a single-port rule is revoked ` +
      `automatically, because revoking a range removes more than the detected exposure`
    );
  }

  return { allowed: true, reason: "matches whitelisted single-port rule" };
}

export function buildRevokeInput(finding) {
  const isIpv6 = typeof finding.cidr === "string" && finding.cidr.includes(":");

  return {
    GroupId: finding.resourceId,
    IpPermissions: [{
      IpProtocol: finding.ipProtocol,
      FromPort: finding.fromPort,
      ToPort: finding.toPort,
      ...(isIpv6
        ? { Ipv6Ranges: [{ CidrIpv6: finding.cidr }] }
        : { IpRanges: [{ CidrIp: finding.cidr }] })
    }]
  };
}

export async function fix(finding, options = {}) {
  const check = checkWhitelist(finding, options);

  if (!check.allowed) {
    console.log(`⏭️  Skipping remediation of ${finding?.findingId}: ${check.reason}`);
    return { remediated: false, skipped: true, reason: check.reason };
  }

  const dryRun = options.dryRun ?? !config.remediationEnabled;
  const client = options.client ?? new EC2Client({ region: config.region });
  const input = buildRevokeInput(finding);

  try {
    await client.send(new RevokeSecurityGroupIngressCommand({ ...input, DryRun: dryRun }));

    // A dry run that does NOT throw is unexpected; treat it as not-remediated
    // rather than claiming a fix that never happened.
    if (dryRun) {
      return {
        remediated: false,
        dryRun: true,
        wouldRemediate: true,
        reason: "dry run: AWS accepted the request without validating as a dry run"
      };
    }

    console.log(
      `🔧 Revoked ${finding.ipProtocol}/${finding.port} from ${finding.cidr} ` +
      `on ${finding.resourceId}`
    );
    return { remediated: true, timestamp: new Date().toISOString() };
  } catch (error) {
    // This is the SUCCESS path for a dry run: AWS confirms it would have worked.
    if (dryRun && (error.name === "DryRunOperation" || error.Code === "DryRunOperation")) {
      console.log(
        `✅ Dry run OK — would revoke ${finding.ipProtocol}/${finding.port} from ` +
        `${finding.cidr} on ${finding.resourceId} (set enable_remediation to act)`
      );
      return {
        remediated: false,
        dryRun: true,
        wouldRemediate: true,
        reason: "dry run succeeded; remediation is disabled"
      };
    }

    // UnauthorizedOperation during a dry run means the IAM policy is missing the
    // revoke permission — a configuration problem worth surfacing clearly.
    console.error(`❌ Failed to revoke rule on ${finding.resourceId}: ${error.message}`);
    return {
      remediated: false,
      error: error.message,
      errorName: error.name
    };
  }
}

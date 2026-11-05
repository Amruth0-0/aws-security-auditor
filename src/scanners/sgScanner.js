import { EC2Client, paginateDescribeSecurityGroups } from "@aws-sdk/client-ec2";
import config from "../config/env.js";

const WATCHED_PORTS = [
  { port: 22, label: "SSH" },
  { port: 3389, label: "RDP" }
];

const ALL_PROTOCOLS = "-1";
const TCP_PROTOCOLS = new Set(["tcp", "6"]);

export function coversPort(permission, port) {
  if (!permission) return false;

  const protocol = String(permission.IpProtocol ?? "");

  if (protocol === ALL_PROTOCOLS) return true;

  if (!TCP_PROTOCOLS.has(protocol.toLowerCase())) return false;

  const { FromPort, ToPort } = permission;
  if (typeof FromPort !== "number" || typeof ToPort !== "number") return false;

  return FromPort <= port && port <= ToPort;
}

export function worldOpenCidrs(permission) {
  if (!permission) return [];

  const isDefaultRoute = (cidr) =>
    typeof cidr === "string" && cidr.split("/")[1] === "0";

  const v4 = (permission.IpRanges || [])
    .map(range => range.CidrIp)
    .filter(isDefaultRoute);

  const v6 = (permission.Ipv6Ranges || [])
    .map(range => range.CidrIpv6)
    .filter(isDefaultRoute);

  return [...v4, ...v6];
}


function buildFindingId({ groupId, port, ipProtocol, cidr }) {
  return `securityGroup#${groupId}#OPEN_PORT#${port}#${ipProtocol}#${cidr}`;
}

export async function scan() {
  const client = new EC2Client({ region: config.region });

  const findings = [];

  try {
    const pages = paginateDescribeSecurityGroups({ client }, {});

    for await (const page of pages) {
      for (const sg of page.SecurityGroups || []) {
        for (const permission of sg.IpPermissions || []) {
          const exposedCidrs = worldOpenCidrs(permission);
          if (exposedCidrs.length === 0) continue;

          for (const { port, label } of WATCHED_PORTS) {
            if (!coversPort(permission, port)) continue;

            for (const cidr of exposedCidrs) {
              const ipProtocol = String(permission.IpProtocol);

              findings.push({
                findingId: buildFindingId({
                  groupId: sg.GroupId,
                  port,
                  ipProtocol,
                  cidr
                }),
                resourceType: "securityGroup",
                type: "OPEN_PORT",
                resourceId: sg.GroupId,
                resourceName: sg.GroupName,
                vpcId: sg.VpcId,

                port,
                service: label,
                ipProtocol,
                fromPort: permission.FromPort ?? null,
                toPort: permission.ToPort ?? null,
                cidr,

                autoRemediable: true,
                description:
                  `Security group ${sg.GroupName} (${sg.GroupId}) exposes ${label} ` +
                  `(port ${port}) to ${cidr} via ${ipProtocol} ` +
                  `${permission.FromPort ?? "all"}-${permission.ToPort ?? "all"}`
              });
            }
          }
        }
      }
    }

    return findings;
  } catch (error) {
    console.error("Error scanning security groups: ", error.message);
    throw error;
  }
}

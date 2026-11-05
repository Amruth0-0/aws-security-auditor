import {
  EC2Client,
  paginateDescribeInstances,
  paginateDescribeRouteTables,
  paginateDescribeSubnets
} from "@aws-sdk/client-ec2";
import {
  IAMClient,
  GetInstanceProfileCommand,
  ListAttachedRolePoliciesCommand,
  ListRolePoliciesCommand,
  GetRolePolicyCommand,
  GetPolicyCommand,
  GetPolicyVersionCommand
} from "@aws-sdk/client-iam";
import config from "../config/env.js";


function isInstancePublic({ inPublicSubnet, hasPublicIp }) {
  return inPublicSubnet === true && hasPublicIp === true;
}

export async function resolvePublicSubnets(ec2) {
  const explicitlyAssociated = new Set();
  const publicSubnetIds = new Set();
  const mainRouteTableIsPublicByVpc = new Map();

  for await (const page of paginateDescribeRouteTables({ client: ec2 }, {})) {
    for (const rt of page.RouteTables || []) {
      const hasIgwRoute = (rt.Routes || []).some(
        route => typeof route.GatewayId === "string" && route.GatewayId.startsWith("igw-")
      );

      for (const assoc of rt.Associations || []) {
        if (assoc.SubnetId) {
          explicitlyAssociated.add(assoc.SubnetId);
          if (hasIgwRoute) publicSubnetIds.add(assoc.SubnetId);
        } else if (assoc.Main === true && rt.VpcId) {
          mainRouteTableIsPublicByVpc.set(rt.VpcId, hasIgwRoute);
        }
      }
    }
  }

  // Resolve the implicit case for every subnet with no explicit association.
  const subnetVpc = new Map();
  for await (const page of paginateDescribeSubnets({ client: ec2 }, {})) {
    for (const subnet of page.Subnets || []) {
      subnetVpc.set(subnet.SubnetId, subnet.VpcId);
      if (!explicitlyAssociated.has(subnet.SubnetId)
          && mainRouteTableIsPublicByVpc.get(subnet.VpcId) === true) {
        publicSubnetIds.add(subnet.SubnetId);
      }
    }
  }

  return { publicSubnetIds, subnetVpc };
}

export function analysePolicyDocument(doc) {
  const result = { wildcardAction: false, wildcardResource: false, admin: false, statements: [] };
  if (!doc) return result;

  // Statement may be a single object or an array.
  const statements = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];

  for (const statement of statements) {
    if (!statement || statement.Effect !== "Allow") continue;

    // Action and Resource may each be a string or an array of strings.
    const actions = [].concat(statement.Action ?? statement.NotAction ?? []);
    const resources = [].concat(statement.Resource ?? []);

    const wildcardAction = actions.some(
      a => typeof a === "string" && (a === "*" || a.endsWith(":*"))
    );
    const wildcardResource = resources.some(r => r === "*");

    if (wildcardAction) result.wildcardAction = true;
    if (wildcardResource) result.wildcardResource = true;

    // Full administrator access: any action on any resource.
    if (actions.includes("*") && wildcardResource) result.admin = true;

    if (wildcardAction || wildcardResource) {
      result.statements.push({
        actions: actions.slice(0, 5),
        resources: resources.slice(0, 5)
      });
    }
  }

  return result;
}

export function parsePolicyDocument(raw) {
  if (!raw) return null;
  if (typeof raw === "object") return raw;
  try {
    return JSON.parse(raw);
  } catch {
    try {
      return JSON.parse(decodeURIComponent(raw));
    } catch {
      return null;
    }
  }
}

async function analyseRole(iam, roleName, cache) {
  if (cache.has(roleName)) return cache.get(roleName);

  const summary = {
    roleName,
    wildcardAction: false,
    wildcardResource: false,
    admin: false,
    offendingPolicies: [],
    partial: false            // true if we could not read every policy
  };

  const merge = (policyName, analysis) => {
    if (analysis.wildcardAction) summary.wildcardAction = true;
    if (analysis.wildcardResource) summary.wildcardResource = true;
    if (analysis.admin) summary.admin = true;
    if (analysis.statements.length > 0) {
      summary.offendingPolicies.push({ policyName, statements: analysis.statements });
    }
  };

  try {
    // Managed policies: list -> get default version -> fetch the document.
    const attached = await iam.send(new ListAttachedRolePoliciesCommand({ RoleName: roleName }));

    for (const policy of attached.AttachedPolicies || []) {
      // Short-circuit: once admin is proven, further documents cannot make it
      // worse, and each one costs two more API calls.
      if (summary.admin) break;

      try {
        const meta = await iam.send(new GetPolicyCommand({ PolicyArn: policy.PolicyArn }));
        const version = await iam.send(new GetPolicyVersionCommand({
          PolicyArn: policy.PolicyArn,
          VersionId: meta.Policy?.DefaultVersionId
        }));
        merge(policy.PolicyName, analysePolicyDocument(
          parsePolicyDocument(version.PolicyVersion?.Document)
        ));
      } catch (error) {
        summary.partial = true;
        console.warn(`Could not read managed policy ${policy.PolicyArn}: ${error.message}`);
      }
    }

    // Inline policies live on the role itself and are fetched differently.
    const inline = await iam.send(new ListRolePoliciesCommand({ RoleName: roleName }));

    for (const policyName of inline.PolicyNames || []) {
      try {
        const doc = await iam.send(new GetRolePolicyCommand({
          RoleName: roleName,
          PolicyName: policyName
        }));
        merge(policyName, analysePolicyDocument(parsePolicyDocument(doc.PolicyDocument)));
      } catch (error) {
        summary.partial = true;
        console.warn(`Could not read inline policy ${policyName}: ${error.message}`);
      }
    }
  } catch (error) {
    summary.partial = true;
    console.warn(`Could not analyse role ${roleName}: ${error.message}`);
  }

  cache.set(roleName, summary);
  return summary;
}

function instanceProfileNameFromArn(arn) {
  // arn:aws:iam::123456789012:instance-profile/MyProfile
  return typeof arn === "string" ? arn.split("/").pop() : undefined;
}

function tagValue(tags, key) {
  const match = (tags || []).find(t => String(t.Key).toLowerCase() === key.toLowerCase());
  return match?.Value;
}


export async function scan() {
  const ec2 = new EC2Client({ region: config.region });
  const iam = new IAMClient({ region: config.region });

  const { publicSubnetIds } = await resolvePublicSubnets(ec2);

  const roleCache = new Map();
  const contexts = [];

  for await (const page of paginateDescribeInstances({ client: ec2 }, {})) {
    for (const reservation of page.Reservations || []) {
      for (const instance of reservation.Instances || []) {
        // Terminated instances cannot be attacked; skip them so they do not
        // inflate the findings table after a demo teardown.
        const state = instance.State?.Name;
        if (state === "terminated" || state === "shutting-down") continue;

        const inPublicSubnet = publicSubnetIds.has(instance.SubnetId);
        const hasPublicIp = Boolean(instance.PublicIpAddress);

        const profileName = instanceProfileNameFromArn(instance.IamInstanceProfile?.Arn);
        let role = null;

        if (profileName) {
          try {
            const profile = await iam.send(
              new GetInstanceProfileCommand({ InstanceProfileName: profileName })
            );
            // An instance profile holds at most one role in practice.
            const roleName = profile.InstanceProfile?.Roles?.[0]?.RoleName;
            if (roleName) role = await analyseRole(iam, roleName, roleCache);
          } catch (error) {
            console.warn(`Could not read instance profile ${profileName}: ${error.message}`);
          }
        }

        const sensitiveTag = tagValue(instance.Tags, "Sensitive");

        contexts.push({
          instanceId: instance.InstanceId,
          state,
          subnetId: instance.SubnetId,
          vpcId: instance.VpcId,
          securityGroupIds: (instance.SecurityGroups || []).map(sg => sg.GroupId),

          inPublicSubnet,
          hasPublicIp,
          isPublic: isInstancePublic({ inPublicSubnet, hasPublicIp }),

          roleName: role?.roleName ?? null,
          hasWildcardIamPolicy: Boolean(role && (role.wildcardAction || role.wildcardResource)),
          hasAdminIamPolicy: Boolean(role?.admin),
          offendingPolicies: role?.offendingPolicies ?? [],

          sensitive: String(sensitiveTag).toLowerCase() === "true",
          name: tagValue(instance.Tags, "Name") ?? null,

          // True when a policy or profile could not be read. The handler treats
          // an incomplete picture as unsafe and suppresses remediation.
          partial: Boolean(role?.partial)
        });
      }
    }
  }

  return contexts;
}

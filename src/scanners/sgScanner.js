import { EC2Client, DescribeSecurityGroupsCommand } from "@aws-sdk/client-ec2";

/* Scanner for Security Groups 
   Scans in the account for ssh(22) or rdp(3389)
   Open to 0.0.0.0/0 (anywhere on the internet)
*/

export async function scan() {
  const client = new EC2Client({
    region: process.env.AWS_REGION || 'us-east-1'
  });

  const findings = [];

  try {
    const command = new DescribeSecurityGroupsCommand({});
    const response = await client.send(command);

    for (const sg of response.SecurityGroups || []) {
      for (const permission of sg.IpPermissions || []) {
        const port = permission.FromPort;
        const isSSH = port === 22;
        const isRDP = port === 3389;

        if (!isSSH && !isRDP) {
          continue;
        }

        const isPublic = permission.IpRanges?.some(ip => ip.CidrIp === "0.0.0.0/0");

        if (isPublic) {
          findings.push({
            type: "OPEN_PORT",
            resourceId: sg.GroupId,
            resourceName: sg.GroupName,
            port: port,
            protocol: permission.IpProtocol,
            autoRemediable: true,
            vpcId: sg.VpcId,
            description: `Security group ${sg.GroupName} (${sg.GroupId}) has ${isSSH ? 'SSH' : 'RDP'} open to 0.0.0.0/0`
          });
        }
      }
    }

    return findings;
  } catch (error) {
    console.error("Error scanning security groups: ", error.message);
    throw error;
  }
}
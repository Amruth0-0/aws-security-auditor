import { describe, it, expect, vi } from "vitest";
import { checkWhitelist, buildRevokeInput, fix } from "../../src/remediation/remediateSG.js";

const WHITELIST = { ports: [22, 3389], cidrs: ["0.0.0.0/0"] };
const opts = (extra = {}) => ({ whitelist: WHITELIST, excludedSecurityGroupIds: [], ...extra });

const safeFinding = {
    findingId: "securityGroup#sg-1#OPEN_PORT#22#tcp#0.0.0.0/0",
    type: "OPEN_PORT",
    resourceId: "sg-1",
    port: 22,
    ipProtocol: "tcp",
    fromPort: 22,
    toPort: 22,
    cidr: "0.0.0.0/0",
    autoRemediable: true,
    severity: "LOW",
    contextIncomplete: false
};

describe("checkWhitelist — the happy path", () => {
    it("allows a whitelisted single-port TCP rule open to the world", () => {
        const result = checkWhitelist(safeFinding, opts());
        expect(result.allowed).toBe(true);
    });

    it("allows RDP as well as SSH", () => {
        const rdp = { ...safeFinding, port: 3389, fromPort: 3389, toPort: 3389 };
        expect(checkWhitelist(rdp, opts()).allowed).toBe(true);
    });
});

describe("gate 1-3: the finding must be the right kind and not escalated", () => {
    it("refuses a non-OPEN_PORT finding", () => {
        const result = checkWhitelist({ ...safeFinding, type: "PUBLIC_BUCKET" }, opts());
        expect(result.allowed).toBe(false);
        expect(result.reason).toMatch(/not remediable/);
    });

    it("refuses when the scanner did not mark it auto-remediable", () => {
        const result = checkWhitelist({ ...safeFinding, autoRemediable: false }, opts());
        expect(result.allowed).toBe(false);
    });

    it("refuses a HIGH severity finding even if everything else matches", () => {
        // The human-in-the-loop guarantee, re-checked here rather than trusted
        // from the caller.
        const result = checkWhitelist({ ...safeFinding, severity: "HIGH" }, opts());
        expect(result.allowed).toBe(false);
        expect(result.reason).toMatch(/escalated/);
    });
});

describe("gate 4: fail closed on an incomplete risk picture", () => {
    it("refuses when the IAM context was incomplete", () => {
        // If the IAM scan failed, the score is an under-estimate, so LOW cannot
        // be trusted to mean safe.
        const result = checkWhitelist({ ...safeFinding, contextIncomplete: true }, opts());
        expect(result.allowed).toBe(false);
        expect(result.reason).toMatch(/incomplete/);
    });
});

describe("gate 5: the exclusion list always wins", () => {
    it("refuses an excluded security group", () => {
        const result = checkWhitelist(safeFinding, opts({ excludedSecurityGroupIds: ["sg-1"] }));
        expect(result.allowed).toBe(false);
        expect(result.reason).toMatch(/exclusion list/);
    });
});

describe("gate 6: the whitelist is fail-closed", () => {
    it("permits nothing when the whitelist is empty", () => {
        // A deployment that forgets to configure the whitelist must do no damage.
        const result = checkWhitelist(safeFinding, opts({ whitelist: {} }));
        expect(result.allowed).toBe(false);
        expect(result.reason).toMatch(/whitelist is empty/);
    });

    it("permits nothing when the whitelist has ports but no CIDRs", () => {
        const result = checkWhitelist(safeFinding, opts({ whitelist: { ports: [22] } }));
        expect(result.allowed).toBe(false);
    });

    it("refuses a non-whitelisted port", () => {
        const mysql = { ...safeFinding, port: 3306, fromPort: 3306, toPort: 3306 };
        expect(checkWhitelist(mysql, opts()).reason).toMatch(/port 3306 is not whitelisted/);
    });

    it("refuses a non-whitelisted CIDR", () => {
        const scoped = { ...safeFinding, cidr: "10.0.0.0/8" };
        expect(checkWhitelist(scoped, opts()).reason).toMatch(/not whitelisted/);
    });
});

describe("gate 7: broad rules are detected but never auto-revoked", () => {
    it("refuses an all-traffic rule (IpProtocol -1)", () => {
        const allTraffic = {
            ...safeFinding, ipProtocol: "-1", fromPort: null, toPort: null
        };
        const result = checkWhitelist(allTraffic, opts());
        expect(result.allowed).toBe(false);
        expect(result.reason).toMatch(/too broad/);
    });

    it("refuses an all-TCP range (0-65535)", () => {
        const allTcp = { ...safeFinding, fromPort: 0, toPort: 65535 };
        const result = checkWhitelist(allTcp, opts());
        expect(result.allowed).toBe(false);
        expect(result.reason).toMatch(/spans ports 0-65535/);
    });

    it("refuses a narrow range that merely contains the port", () => {
        const range = { ...safeFinding, fromPort: 20, toPort: 30 };
        expect(checkWhitelist(range, opts()).allowed).toBe(false);
    });

    it("refuses UDP", () => {
        const udp = { ...safeFinding, ipProtocol: "udp" };
        expect(checkWhitelist(udp, opts()).reason).toMatch(/too broad/);
    });
});

describe("missing data is refused, never guessed", () => {
    it.each([
        ["resourceId", { resourceId: undefined }],
        ["ipProtocol", { ipProtocol: undefined }],
        ["cidr", { cidr: undefined }],
        ["port", { port: undefined }]
    ])("refuses a finding with no %s", (_label, override) => {
        const result = checkWhitelist({ ...safeFinding, ...override }, opts());
        expect(result.allowed).toBe(false);
    });

    it("refuses a null finding without throwing", () => {
        expect(checkWhitelist(null, opts()).allowed).toBe(false);
    });
});

describe("buildRevokeInput — the exact tuple", () => {
    it("builds an IPv4 revoke matching only the detected rule", () => {
        expect(buildRevokeInput(safeFinding)).toEqual({
            GroupId: "sg-1",
            IpPermissions: [{
                IpProtocol: "tcp",
                FromPort: 22,
                ToPort: 22,
                IpRanges: [{ CidrIp: "0.0.0.0/0" }]
            }]
        });
    });

    it("uses Ipv6Ranges for an IPv6 CIDR", () => {
        const input = buildRevokeInput({ ...safeFinding, cidr: "::/0" });
        expect(input.IpPermissions[0].Ipv6Ranges).toEqual([{ CidrIpv6: "::/0" }]);
        expect(input.IpPermissions[0].IpRanges).toBeUndefined();
    });
});

describe("fix — the actual call", () => {
    const mockClient = (behaviour) => ({ send: vi.fn(behaviour) });

    it("skips without calling AWS when a gate refuses", async () => {
        const client = mockClient(async () => ({}));
        const result = await fix({ ...safeFinding, severity: "HIGH" }, opts({ client }));

        expect(client.send).not.toHaveBeenCalled();
        expect(result.remediated).toBe(false);
        expect(result.skipped).toBe(true);
    });

    it("treats a DryRunOperation error as 'this would have worked'", async () => {
        // AWS's own dry run: it validates permissions and arguments, then
        // refuses to act and throws DryRunOperation. That proves the whole path
        // before anything is allowed to delete a real rule.
        const client = mockClient(async () => {
            throw Object.assign(new Error("Request would have succeeded"), {
                name: "DryRunOperation"
            });
        });
        const result = await fix(safeFinding, opts({ client, dryRun: true }));

        expect(result.remediated).toBe(false);
        expect(result.dryRun).toBe(true);
        expect(result.wouldRemediate).toBe(true);
    });

    it("passes DryRun: true to AWS when in dry-run mode", async () => {
        const client = mockClient(async () => {
            throw Object.assign(new Error("x"), { name: "DryRunOperation" });
        });
        await fix(safeFinding, opts({ client, dryRun: true }));

        expect(client.send.mock.calls[0][0].input.DryRun).toBe(true);
    });

    it("revokes for real when remediation is enabled", async () => {
        const client = mockClient(async () => ({}));
        const result = await fix(safeFinding, opts({ client, dryRun: false }));

        expect(result.remediated).toBe(true);
        expect(result.timestamp).toBeTruthy();
        expect(client.send.mock.calls[0][0].input).toMatchObject({
            GroupId: "sg-1",
            DryRun: false
        });
    });

    it("returns an error instead of throwing when AWS refuses", async () => {
        // A failed remediation must not abort the scan that found it.
        const client = mockClient(async () => {
            throw Object.assign(new Error("not authorized"), { name: "UnauthorizedOperation" });
        });
        const result = await fix(safeFinding, opts({ client, dryRun: false }));

        expect(result.remediated).toBe(false);
        expect(result.errorName).toBe("UnauthorizedOperation");
        expect(result.error).toMatch(/not authorized/);
    });

    it("never throws, whatever happens", async () => {
        const client = mockClient(async () => { throw new Error("catastrophe"); });
        await expect(fix(safeFinding, opts({ client, dryRun: false }))).resolves.toBeTruthy();
    });
});

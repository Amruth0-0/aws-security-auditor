import { describe, it, expect } from "vitest";
import { coversPort, worldOpenCidrs } from "../../src/scanners/sgScanner.js";

const SSH = 22;
const RDP = 3389;

describe("coversPort — port ranges, not single ports", () => {
    it("catches an exact SSH rule (this one always worked)", () => {
        expect(coversPort({ IpProtocol: "tcp", FromPort: 22, ToPort: 22 }, SSH)).toBe(true);
    });

    it("catches ALL TCP open (0-65535) — MISSED by the old FromPort === 22 check", () => {
        expect(coversPort({ IpProtocol: "tcp", FromPort: 0, ToPort: 65535 }, SSH)).toBe(true);
        expect(coversPort({ IpProtocol: "tcp", FromPort: 0, ToPort: 65535 }, RDP)).toBe(true);
    });

    it("catches ALL TRAFFIC (IpProtocol '-1', no port fields) — MISSED before", () => {
        // AWS omits FromPort/ToPort entirely for "-1". This is the worst-case
        // rule a panicking developer creates, and it used to report as clean.
        expect(coversPort({ IpProtocol: "-1" }, SSH)).toBe(true);
        expect(coversPort({ IpProtocol: "-1" }, RDP)).toBe(true);
    });

    it("catches a range that merely contains the port (20-30) — MISSED before", () => {
        expect(coversPort({ IpProtocol: "tcp", FromPort: 20, ToPort: 30 }, SSH)).toBe(true);
    });

    it("catches the numeric TCP protocol form ('6')", () => {
        expect(coversPort({ IpProtocol: "6", FromPort: 20, ToPort: 30 }, SSH)).toBe(true);
    });

    it("does not flag a range that excludes the port", () => {
        expect(coversPort({ IpProtocol: "tcp", FromPort: 80, ToPort: 443 }, SSH)).toBe(false);
        expect(coversPort({ IpProtocol: "tcp", FromPort: 23, ToPort: 65535 }, SSH)).toBe(false);
    });

    it("does not flag UDP on 22 — SSH is a TCP service", () => {
        expect(coversPort({ IpProtocol: "udp", FromPort: 22, ToPort: 22 }, SSH)).toBe(false);
    });

    it("does not flag ICMP", () => {
        expect(coversPort({ IpProtocol: "icmp", FromPort: -1, ToPort: -1 }, SSH)).toBe(false);
    });

    it("does not guess when a TCP rule is missing its bounds", () => {
        expect(coversPort({ IpProtocol: "tcp" }, SSH)).toBe(false);
    });

    it("handles null/undefined input without throwing", () => {
        expect(coversPort(null, SSH)).toBe(false);
        expect(coversPort(undefined, SSH)).toBe(false);
    });
});

describe("worldOpenCidrs — what counts as 'the internet'", () => {
    it("detects IPv4 0.0.0.0/0", () => {
        expect(worldOpenCidrs({ IpRanges: [{ CidrIp: "0.0.0.0/0" }] })).toEqual(["0.0.0.0/0"]);
    });

    it("detects IPv6 ::/0 — never inspected by the old scanner", () => {
        expect(worldOpenCidrs({ Ipv6Ranges: [{ CidrIpv6: "::/0" }] })).toEqual(["::/0"]);
    });

    it("returns every offending CIDR so each gets its own finding", () => {
        const result = worldOpenCidrs({
            IpRanges: [{ CidrIp: "10.0.0.0/16" }, { CidrIp: "0.0.0.0/0" }],
            Ipv6Ranges: [{ CidrIpv6: "::/0" }]
        });
        expect(result).toEqual(["0.0.0.0/0", "::/0"]);
    });

    it("ignores a scoped CIDR", () => {
        expect(worldOpenCidrs({ IpRanges: [{ CidrIp: "10.0.0.0/16" }] })).toEqual([]);
        expect(worldOpenCidrs({ IpRanges: [{ CidrIp: "203.0.113.4/32" }] })).toEqual([]);
    });

    it("does not treat SG-to-SG references as public", () => {
        // A missing IpRanges must read as "not public", not "unknown, assume bad".
        expect(worldOpenCidrs({ UserIdGroupPairs: [{ GroupId: "sg-123" }] })).toEqual([]);
    });

    it("does not treat prefix lists as public", () => {
        expect(worldOpenCidrs({ PrefixListIds: [{ PrefixListId: "pl-123" }] })).toEqual([]);
    });

    it("handles null/undefined input without throwing", () => {
        expect(worldOpenCidrs(null)).toEqual([]);
        expect(worldOpenCidrs(undefined)).toEqual([]);
    });
});

describe("the two predicates together", () => {
    // The regression case: all traffic, all ports, whole internet. Every field
    // the old scanner relied on is either absent or unequal to 22.
    const worstCase = { IpProtocol: "-1", IpRanges: [{ CidrIp: "0.0.0.0/0" }] };

    it("flags the worst possible rule for both watched ports", () => {
        expect(worldOpenCidrs(worstCase).length).toBeGreaterThan(0);
        expect(coversPort(worstCase, SSH)).toBe(true);
        expect(coversPort(worstCase, RDP)).toBe(true);
    });

    it("leaves a correctly scoped HTTPS rule alone", () => {
        const safe = { IpProtocol: "tcp", FromPort: 443, ToPort: 443, IpRanges: [{ CidrIp: "10.0.0.0/16" }] };
        expect(worldOpenCidrs(safe)).toEqual([]);
        expect(coversPort(safe, SSH)).toBe(false);
    });
});

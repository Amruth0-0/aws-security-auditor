import { describe, it, expect } from "vitest";
import {
    score,
    scoreAll,
    contextsForFinding,
    worstCaseContext,
    buildAttackPathFindings,
    BASE_POINTS,
    POINTS,
    DEFAULT_THRESHOLD,
    SEVERITY
} from "../../src/analysis/blastRadius.js";

const openPortFinding = {
    findingId: "securityGroup#sg-1#OPEN_PORT#22#tcp#0.0.0.0/0",
    resourceType: "securityGroup",
    type: "OPEN_PORT",
    resourceId: "sg-1",
    port: 22,
    ipProtocol: "tcp",
    fromPort: 22,
    toPort: 22,
    cidr: "0.0.0.0/0",
    autoRemediable: true
};


const ctx = (overrides = {}) => ({
    instanceId: "i-123",
    securityGroupIds: ["sg-1"],
    inPublicSubnet: false,
    hasPublicIp: false,
    isPublic: false,
    hasWildcardIamPolicy: false,
    hasAdminIamPolicy: false,
    sensitive: false,
    partial: false,
    roleName: null,
    ...overrides
});

describe("the chain — no single factor escalates, a combination does", () => {
    it("open SSH attached to nothing is LOW and auto-remediable", () => {
        const result = score(openPortFinding, []);
        expect(result.blastRadiusScore).toBe(BASE_POINTS.OPEN_PORT);
        expect(result.severity).toBe(SEVERITY.LOW);
        expect(result.autoRemediable).toBe(true);
        expect(result.escalate).toBe(false);
    });

    it("open SSH on a publicly reachable instance is still LOW — revoking is safe", () => {
        const result = score(openPortFinding, [ctx({ isPublic: true })]);
        expect(result.blastRadiusScore).toBe(BASE_POINTS.OPEN_PORT + POINTS.PUBLICLY_REACHABLE);
        expect(result.blastRadiusScore).toBeLessThan(DEFAULT_THRESHOLD);
        expect(result.severity).toBe(SEVERITY.LOW);
        expect(result.autoRemediable).toBe(true);
    });

    it("open SSH plus a wildcard role but NOT public is still LOW", () => {
        const result = score(openPortFinding, [ctx({ hasWildcardIamPolicy: true })]);
        expect(result.blastRadiusScore).toBe(BASE_POINTS.OPEN_PORT + POINTS.WILDCARD_IAM);
        expect(result.severity).toBe(SEVERITY.LOW);
        expect(result.autoRemediable).toBe(true);
    });

    it("public AND wildcard together reach the threshold -> HIGH, escalated", () => {
        const result = score(openPortFinding, [
            ctx({ isPublic: true, hasWildcardIamPolicy: true })
        ]);
        expect(result.blastRadiusScore).toBe(
            BASE_POINTS.OPEN_PORT + POINTS.PUBLICLY_REACHABLE + POINTS.WILDCARD_IAM
        );
        expect(result.blastRadiusScore).toBeGreaterThanOrEqual(DEFAULT_THRESHOLD);
        expect(result.severity).toBe(SEVERITY.HIGH);
        expect(result.escalate).toBe(true);
        // The human-in-the-loop guarantee.
        expect(result.autoRemediable).toBe(false);
    });

    it("explains itself — riskFactors names every factor that was applied", () => {
        const result = score(openPortFinding, [
            ctx({ isPublic: true, hasWildcardIamPolicy: true, hasAdminIamPolicy: true, sensitive: true })
        ]);
        expect(result.riskFactors).toHaveLength(4);
        expect(result.riskFactors.join(" ")).toMatch(/publicly reachable/i);
        expect(result.riskFactors.join(" ")).toMatch(/administrator/i);
        expect(result.riskFactors.join(" ")).toMatch(/sensitive/i);
    });
});

describe("scoring rules", () => {
    it("adds admin points on top of wildcard points", () => {
        const result = score(openPortFinding, [
            ctx({ isPublic: true, hasWildcardIamPolicy: true, hasAdminIamPolicy: true })
        ]);
        expect(result.blastRadiusScore).toBe(
            BASE_POINTS.OPEN_PORT + POINTS.PUBLICLY_REACHABLE + POINTS.WILDCARD_IAM + POINTS.ADMIN_IAM
        );
    });

    it("adds points for a Sensitive tag", () => {
        const plain = score(openPortFinding, [ctx({ isPublic: true })]);
        const tagged = score(openPortFinding, [ctx({ isPublic: true, sensitive: true })]);
        expect(tagged.blastRadiusScore - plain.blastRadiusScore).toBe(POINTS.SENSITIVE_TAG);
    });

    it("respects a custom threshold", () => {
        const result = score(openPortFinding, [ctx({ isPublic: true })], { threshold: 9 });
        expect(result.severity).toBe(SEVERITY.HIGH);
        expect(result.autoRemediable).toBe(false);
    });

    it("scores an unknown finding type on default base points", () => {
        const result = score({ type: "SOMETHING_NEW", resourceId: "x" }, []);
        expect(result.blastRadiusScore).toBe(3);
    });

    it("does not mutate the finding it was given", () => {
        const input = { ...openPortFinding };
        score(input, [ctx({ isPublic: true, hasWildcardIamPolicy: true })]);
        expect(input.severity).toBeUndefined();
        expect(input.autoRemediable).toBe(true);
    });
});

describe("autoRemediable may only ever be taken away, never granted", () => {
    it("keeps an unencrypted RDS finding non-remediable even at a low score", () => {
        const rds = {
            findingId: "rdsInstance#db-1#UNENCRYPTED_RDS",
            type: "UNENCRYPTED_RDS",
            resourceId: "db-1",
            autoRemediable: false
        };
        const result = score(rds, []);
        expect(result.severity).toBe(SEVERITY.LOW);
        // Nothing in this project can encrypt an existing RDS instance, so a low
        // score must not imply it is fixable.
        expect(result.autoRemediable).toBe(false);
    });

    it("keeps a public bucket finding non-remediable", () => {
        const bucket = { type: "PUBLIC_BUCKET", resourceId: "my-bucket", autoRemediable: false };
        expect(score(bucket, []).autoRemediable).toBe(false);
    });

    it("never marks a scanner error as remediable", () => {
        const err = { type: "SCANNER_ERROR", resourceId: "rdsInstances", autoRemediable: false };
        const result = score(err, []);
        expect(result.blastRadiusScore).toBe(0);
        expect(result.autoRemediable).toBe(false);
    });
});

describe("contextsForFinding — the join that makes chaining possible", () => {
    it("links an OPEN_PORT finding to instances using that security group", () => {
        const contexts = [
            ctx({ instanceId: "i-match", securityGroupIds: ["sg-1", "sg-9"] }),
            ctx({ instanceId: "i-other", securityGroupIds: ["sg-2"] })
        ];
        const matched = contextsForFinding(openPortFinding, contexts);
        expect(matched.map(c => c.instanceId)).toEqual(["i-match"]);
    });

    it("links an ATTACK_PATH finding to its own instance", () => {
        const finding = { resourceType: "ec2Instance", type: "ATTACK_PATH", resourceId: "i-123" };
        expect(contextsForFinding(finding, [ctx()])).toHaveLength(1);
    });

    it("returns nothing for S3 and RDS findings, which have no instance relationship", () => {
        expect(contextsForFinding({ type: "PUBLIC_BUCKET", resourceId: "b" }, [ctx()])).toEqual([]);
    });
});

describe("worstCaseContext — security posture is the weakest link", () => {
    it("takes the worst factor across every instance sharing the group", () => {
        const worst = worstCaseContext([
            ctx({ instanceId: "i-safe" }),
            ctx({ instanceId: "i-danger", isPublic: true, hasWildcardIamPolicy: true })
        ]);
        expect(worst.isPublic).toBe(true);
        expect(worst.hasWildcardIamPolicy).toBe(true);
        expect(worst.instanceIds).toEqual(["i-safe", "i-danger"]);
    });

    it("escalates a shared group because of one dangerous instance", () => {
        const result = score(openPortFinding, [
            ctx({ instanceId: "i-safe" }),
            ctx({ instanceId: "i-danger", isPublic: true, hasWildcardIamPolicy: true })
        ]);
        expect(result.severity).toBe(SEVERITY.HIGH);
        expect(result.relatedInstanceIds).toContain("i-danger");
    });

    it("returns null when nothing matched", () => {
        expect(worstCaseContext([])).toBeNull();
    });
});

describe("fail closed on an incomplete picture", () => {
    it("propagates contextIncomplete so the remediator can refuse", () => {
        const result = score(openPortFinding, [ctx({ partial: true })]);
        expect(result.contextIncomplete).toBe(true);
    });

    it("reports a complete context as complete", () => {
        expect(score(openPortFinding, [ctx()]).contextIncomplete).toBe(false);
    });
});

describe("buildAttackPathFindings — the combination as a finding of its own", () => {
    it("reports a public instance with a wildcard role", () => {
        const findings = buildAttackPathFindings([
            ctx({ instanceId: "i-bad", isPublic: true, hasWildcardIamPolicy: true, roleName: "AppRole" })
        ]);
        expect(findings).toHaveLength(1);
        expect(findings[0].findingId).toBe("ec2Instance#i-bad#ATTACK_PATH");
        expect(findings[0].type).toBe("ATTACK_PATH");
        // Narrowing an IAM policy is a judgement call; never automate it.
        expect(findings[0].autoRemediable).toBe(false);
        expect(findings[0].description).toMatch(/wildcard permissions/);
    });

    it("says administrator access when the role is full admin", () => {
        const findings = buildAttackPathFindings([
            ctx({ isPublic: true, hasAdminIamPolicy: true, hasWildcardIamPolicy: true })
        ]);
        expect(findings[0].description).toMatch(/full administrator access/);
    });

    it("ignores a public instance with a properly scoped role", () => {
        expect(buildAttackPathFindings([ctx({ isPublic: true })])).toEqual([]);
    });

    it("ignores a wildcard role that is not internet reachable", () => {
        expect(buildAttackPathFindings([ctx({ hasWildcardIamPolicy: true })])).toEqual([]);
    });

    it("scores its own output as HIGH once fed back through the engine", () => {
        const contexts = [ctx({ isPublic: true, hasWildcardIamPolicy: true })];
        const [attackPath] = buildAttackPathFindings(contexts);
        const scored = score(attackPath, contexts);
        expect(scored.severity).toBe(SEVERITY.HIGH);
        expect(scored.autoRemediable).toBe(false);
    });
});

describe("scoreAll", () => {
    it("scores a mixed batch against one shared context set", () => {
        const contexts = [ctx({ isPublic: true, hasWildcardIamPolicy: true })];
        const results = scoreAll(
            [openPortFinding, { type: "PUBLIC_BUCKET", resourceId: "b", autoRemediable: false }],
            contexts
        );
        expect(results[0].severity).toBe(SEVERITY.HIGH);
        expect(results[1].severity).toBe(SEVERITY.LOW);
    });

    it("handles empty input", () => {
        expect(scoreAll([], [])).toEqual([]);
    });
});

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/scanners/sgScanner.js", () => ({ scan: vi.fn() }));
vi.mock("../../src/scanners/s3Scanner.js", () => ({ scan: vi.fn() }));
vi.mock("../../src/scanners/rdsScanner.js", () => ({ scan: vi.fn() }));
vi.mock("../../src/scanners/iamRoleScanner.js", () => ({ scan: vi.fn() }));
vi.mock("../../src/remediation/remediateSG.js", () => ({ fix: vi.fn() }));
vi.mock("../../src/storage/findingsRepo.js", () => ({ save: vi.fn() }));
vi.mock("../../src/notify/alerts.js", () => ({ publishAlert: vi.fn() }));

const { scan: scanSG } = await import("../../src/scanners/sgScanner.js");
const { scan: scanS3 } = await import("../../src/scanners/s3Scanner.js");
const { scan: scanRDS } = await import("../../src/scanners/rdsScanner.js");
const { scan: scanIam } = await import("../../src/scanners/iamRoleScanner.js");
const { fix: remediateSG } = await import("../../src/remediation/remediateSG.js");
const { save } = await import("../../src/storage/findingsRepo.js");
const { publishAlert } = await import("../../src/notify/alerts.js");
const { handler } = await import("../../src/handler.js");

const sgFinding = {
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

const s3Finding = {
    findingId: "s3Bucket#my-bucket#PUBLIC_BUCKET",
    resourceType: "s3Bucket",
    type: "PUBLIC_BUCKET",
    resourceId: "my-bucket",
    autoRemediable: false
};

const dangerousContext = {
    instanceId: "i-danger",
    securityGroupIds: ["sg-1"],
    isPublic: true,
    hasWildcardIamPolicy: true,
    hasAdminIamPolicy: false,
    sensitive: false,
    partial: false,
    roleName: "AppRole"
};

const body = (res) => JSON.parse(res.body);

beforeEach(() => {
    vi.clearAllMocks();
    // Mirrors findingsRepo: `remediated` is what decides the stored status.
    save.mockImplementation(async (f) => ({
        ...f,
        status: f.remediated === true ? "REMEDIATED" : "OPEN",
        lastSeenAt: "now"
    }));
    publishAlert.mockResolvedValue(undefined);
    remediateSG.mockResolvedValue({ remediated: false, skipped: true, reason: "test default" });
    scanSG.mockResolvedValue([]);
    scanS3.mockResolvedValue([]);
    scanRDS.mockResolvedValue([]);
    scanIam.mockResolvedValue([]);
});

describe("scanner error isolation", () => {
    it("keeps the other scanners' findings when one scanner throws", async () => {
        scanSG.mockResolvedValue([sgFinding]);
        scanS3.mockResolvedValue([s3Finding]);
        scanRDS.mockRejectedValue(Object.assign(new Error("User is not authorized"), { name: "AccessDenied" }));

        const res = await handler({});

        expect(body(res).failedScanners).toEqual(["rdsInstances"]);
        expect(save).toHaveBeenCalledTimes(3); // 2 real findings + 1 SCANNER_ERROR
        expect(res.statusCode).toBe(207);
    });

    it("turns a failed scanner into a visible SCANNER_ERROR finding", async () => {
        scanRDS.mockRejectedValue(new Error("boom"));

        await handler({});
        const saved = save.mock.calls.map(([f]) => f);
        const errorFinding = saved.find(f => f.type === "SCANNER_ERROR");

        expect(errorFinding.findingId).toBe("scanner#rdsInstances#SCANNER_ERROR");
        expect(errorFinding.autoRemediable).toBe(false);
        expect(errorFinding.description).toContain("NOT checked");
    });

    it("does not throw even when every scanner fails", async () => {
        scanSG.mockRejectedValue(new Error("a"));
        scanS3.mockRejectedValue(new Error("b"));
        scanRDS.mockRejectedValue(new Error("c"));

        const res = await handler({});
        expect(res.statusCode).toBe(207);
        expect(body(res).failedScanners).toHaveLength(3);
    });

    it("reports 200 and alerts normally when everything succeeds", async () => {
        scanSG.mockResolvedValue([sgFinding]);
        scanS3.mockResolvedValue([s3Finding]);

        const res = await handler({});

        expect(res.statusCode).toBe(200);
        expect(body(res).failedScanners).toEqual([]);
        expect(publishAlert).toHaveBeenCalledTimes(1);
    });
});

describe("Phase 8 — scoring is wired into the pipeline", () => {
    it("escalates an open SSH rule on a public instance with a wildcard role", async () => {
        scanSG.mockResolvedValue([sgFinding]);
        scanIam.mockResolvedValue([dangerousContext]);

        const res = await handler({});
        const saved = save.mock.calls.map(([f]) => f);
        const openPort = saved.find(f => f.type === "OPEN_PORT");

        expect(openPort.severity).toBe("HIGH");
        expect(openPort.escalate).toBe(true);
        expect(body(res).highSeverity).toBeGreaterThan(0);
    });

    it("leaves the same rule LOW when no instance uses that group", async () => {
        scanSG.mockResolvedValue([sgFinding]);
        scanIam.mockResolvedValue([{ ...dangerousContext, securityGroupIds: ["sg-other"] }]);

        await handler({});
        const openPort = save.mock.calls.map(([f]) => f).find(f => f.type === "OPEN_PORT");

        expect(openPort.severity).toBe("LOW");
    });

    it("creates ATTACK_PATH findings from the relationships themselves", async () => {
        // No scanner reported anything: the combination IS the finding.
        scanIam.mockResolvedValue([dangerousContext]);

        const res = await handler({});
        const saved = save.mock.calls.map(([f]) => f);
        const attackPath = saved.find(f => f.type === "ATTACK_PATH");

        expect(attackPath.findingId).toBe("ec2Instance#i-danger#ATTACK_PATH");
        expect(attackPath.severity).toBe("HIGH");
        expect(attackPath.autoRemediable).toBe(false);
        expect(body(res).attackPaths).toBe(1);
        expect(body(res).instancesAnalysed).toBe(1);
    });

    it("reports how many instances were analysed", async () => {
        scanIam.mockResolvedValue([dangerousContext, { ...dangerousContext, instanceId: "i-2", isPublic: false, hasWildcardIamPolicy: false }]);
        const res = await handler({});
        expect(body(res).instancesAnalysed).toBe(2);
    });
});

describe("Phase 7 — remediation is attempted only where it is allowed", () => {
    it("attempts remediation on a LOW auto-remediable finding", async () => {
        scanSG.mockResolvedValue([sgFinding]);

        await handler({});

        expect(remediateSG).toHaveBeenCalledTimes(1);
        expect(remediateSG.mock.calls[0][0].findingId).toBe(sgFinding.findingId);
    });

    it("never offers a HIGH finding to the remediator", async () => {
        scanSG.mockResolvedValue([sgFinding]);
        scanIam.mockResolvedValue([dangerousContext]);

        await handler({});

        expect(remediateSG).not.toHaveBeenCalled();
    });

    it("never offers a non-remediable finding type to the remediator", async () => {
        scanS3.mockResolvedValue([s3Finding]);
        scanRDS.mockResolvedValue([{
            findingId: "rdsInstance#db#UNENCRYPTED_RDS",
            type: "UNENCRYPTED_RDS", resourceId: "db", autoRemediable: false
        }]);

        await handler({});

        expect(remediateSG).not.toHaveBeenCalled();
    });

    it("records a successful fix as REMEDIATED and leaves it out of the alert", async () => {
        scanSG.mockResolvedValue([sgFinding]);
        remediateSG.mockResolvedValue({ remediated: true, timestamp: "2026-01-01T00:00:00Z" });

        const res = await handler({});
        const saved = save.mock.calls.map(([f]) => f)[0];

        expect(saved.remediated).toBe(true);
        expect(body(res).remediated).toBe(1);
        expect(body(res).openFindings).toBe(0);
        // Nothing is open, so nobody is emailed. Self-healing should be quiet.
        expect(publishAlert).not.toHaveBeenCalled();
    });

    it("keeps a dry-run finding OPEN and reports what it would have done", async () => {
        scanSG.mockResolvedValue([sgFinding]);
        remediateSG.mockResolvedValue({ remediated: false, dryRun: true, wouldRemediate: true });

        const res = await handler({});

        expect(body(res).wouldRemediate).toBe(1);
        expect(body(res).remediated).toBe(0);
        expect(body(res).openFindings).toBe(1);
    });

    it("carries the refusal reason onto the finding", async () => {
        scanSG.mockResolvedValue([sgFinding]);
        remediateSG.mockResolvedValue({
            remediated: false, skipped: true, reason: "port 22 is not whitelisted"
        });

        await handler({});
        const saved = save.mock.calls.map(([f]) => f)[0];

        expect(saved.remediationSkipped).toBe(true);
        expect(saved.remediationNote).toBe("port 22 is not whitelisted");
    });
});

describe("FAIL CLOSED — a scoring failure must not make the system more destructive", () => {
    it("suppresses ALL remediation when the IAM context scan fails", async () => {
        // Without IAM context every finding scores on base points alone, which
        // looks LOW — so a failure in the scoring layer would make the auditor
        // MORE willing to delete rules. That must never happen.
        scanSG.mockResolvedValue([sgFinding]);
        scanIam.mockRejectedValue(new Error("iam:ListAttachedRolePolicies denied"));

        const res = await handler({});

        expect(remediateSG).not.toHaveBeenCalled();
        expect(body(res).remediationSuppressed).toBe(true);
        expect(body(res).failedScanners).toContain("iamRoles");
        expect(res.statusCode).toBe(207);
    });

    it("still records findings and alerts when scoring is unavailable", async () => {
        scanSG.mockResolvedValue([sgFinding]);
        scanIam.mockRejectedValue(new Error("denied"));

        const res = await handler({});

        // Degraded, not silent: detection still works, only the fixing stops.
        expect(save).toHaveBeenCalledTimes(2); // the finding + the iamRoles error
        expect(publishAlert).toHaveBeenCalledTimes(1);
        expect(body(res).openFindings).toBe(2);
    });

    it("explains the suppression in the SCANNER_ERROR finding", async () => {
        scanIam.mockRejectedValue(new Error("denied"));

        await handler({});
        const saved = save.mock.calls.map(([f]) => f);
        const iamError = saved.find(f => f.resourceId === "iamRoles");

        expect(iamError.description).toMatch(/Remediation is suppressed/);
    });
});

describe("write and alert failures are not fatal", () => {
    it("continues saving after one write fails", async () => {
        scanSG.mockResolvedValue([sgFinding]);
        scanS3.mockResolvedValue([s3Finding]);
        save
            .mockRejectedValueOnce(new Error("throughput exceeded"))
            .mockImplementation(async (f) => ({ ...f, status: "OPEN" }));

        const res = await handler({});

        expect(save).toHaveBeenCalledTimes(2);
        expect(body(res).saveErrors).toHaveLength(1);
        expect(res.statusCode).toBe(207);
    });

    it("does not lose a completed scan when the alert fails", async () => {
        scanSG.mockResolvedValue([sgFinding]);
        publishAlert.mockRejectedValue(new Error("SNS unavailable"));

        const res = await handler({});

        expect(body(res).savedFindings).toBe(1);
        expect(body(res).alertError).toBe("SNS unavailable");
        expect(res.statusCode).toBe(207);
    });
});

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/scanners/sgScanner.js", () => ({ scan: vi.fn() }));
vi.mock("../../src/scanners/s3Scanner.js", () => ({ scan: vi.fn() }));
vi.mock("../../src/scanners/rdsScanner.js", () => ({ scan: vi.fn() }));
vi.mock("../../src/storage/findingsRepo.js", () => ({ save: vi.fn() }));
vi.mock("../../src/notify/alerts.js", () => ({ publishAlert: vi.fn() }));

const { scan: scanSG } = await import("../../src/scanners/sgScanner.js");
const { scan: scanS3 } = await import("../../src/scanners/s3Scanner.js");
const { scan: scanRDS } = await import("../../src/scanners/rdsScanner.js");
const { save } = await import("../../src/storage/findingsRepo.js");
const { publishAlert } = await import("../../src/notify/alerts.js");
const { handler } = await import("../../src/handler.js");

const sgFinding = {
    findingId: "securityGroup#sg-1#OPEN_PORT#22#tcp#0.0.0.0/0",
    resourceType: "securityGroup",
    type: "OPEN_PORT",
    resourceId: "sg-1"
};

const s3Finding = {
    findingId: "s3Bucket#my-bucket#PUBLIC_BUCKET",
    resourceType: "s3Bucket",
    type: "PUBLIC_BUCKET",
    resourceId: "my-bucket"
};

beforeEach(() => {
    vi.clearAllMocks();
    // save() returns the enriched record (it no longer mutates its argument).
    save.mockImplementation(async (f) => ({ ...f, status: "OPEN", lastSeenAt: "now" }));
    publishAlert.mockResolvedValue(undefined);
});

describe("handler — scanner error isolation", () => {
    it("keeps the other scanners' findings when one scanner throws", async () => {
        scanSG.mockResolvedValue([sgFinding]);
        scanS3.mockResolvedValue([s3Finding]);
        scanRDS.mockRejectedValue(Object.assign(new Error("User is not authorized"), { name: "AccessDenied" }));

        const res = await handler({});
        const body = JSON.parse(res.body);

        // Old behaviour: Promise.all rejected, nothing was saved, handler threw.
        expect(body.failedScanners).toEqual(["rdsInstances"]);
        expect(save).toHaveBeenCalledTimes(3); // 2 real findings + 1 SCANNER_ERROR
        expect(body.openFindings).toBe(3);
        expect(res.statusCode).toBe(207);
    });

    it("turns a failed scanner into a visible SCANNER_ERROR finding", async () => {
        scanSG.mockResolvedValue([]);
        scanS3.mockResolvedValue([]);
        scanRDS.mockRejectedValue(new Error("boom"));

        await handler({});

        const saved = save.mock.calls.map(([f]) => f);
        const errorFinding = saved.find(f => f.type === "SCANNER_ERROR");

        // "Could not check" must never be indistinguishable from "nothing found".
        expect(errorFinding).toBeDefined();
        expect(errorFinding.findingId).toBe("scanner#rdsInstances#SCANNER_ERROR");
        expect(errorFinding.autoRemediable).toBe(false);
        expect(errorFinding.description).toContain("NOT checked");
    });

    it("uses a stable findingId so repeated failures upsert instead of flooding", async () => {
        scanSG.mockResolvedValue([]);
        scanS3.mockResolvedValue([]);
        scanRDS.mockRejectedValue(new Error("boom"));

        await handler({});
        const firstId = save.mock.calls.map(([f]) => f.findingId).find(id => id.includes("SCANNER_ERROR"));
        vi.clearAllMocks();
        save.mockImplementation(async (f) => ({ ...f, status: "OPEN" }));
        scanSG.mockResolvedValue([]);
        scanS3.mockResolvedValue([]);
        scanRDS.mockRejectedValue(new Error("boom again, different message"));

        await handler({});
        const secondId = save.mock.calls.map(([f]) => f.findingId).find(id => id.includes("SCANNER_ERROR"));

        expect(secondId).toBe(firstId);
    });

    it("does not throw even when every scanner fails", async () => {
        scanSG.mockRejectedValue(new Error("a"));
        scanS3.mockRejectedValue(new Error("b"));
        scanRDS.mockRejectedValue(new Error("c"));

        // Throwing is the only way to tell Lambda to retry. These failures are
        // deterministic, so retrying would burn three runs and three emails.
        const res = await handler({});
        expect(res.statusCode).toBe(207);
        expect(JSON.parse(res.body).failedScanners).toHaveLength(3);
    });

    it("reports 200 and alerts normally when everything succeeds", async () => {
        scanSG.mockResolvedValue([sgFinding]);
        scanS3.mockResolvedValue([s3Finding]);
        scanRDS.mockResolvedValue([]);

        const res = await handler({});
        const body = JSON.parse(res.body);

        expect(res.statusCode).toBe(200);
        expect(body.message).toBe("Scan completed successfully");
        expect(body.failedScanners).toEqual([]);
        expect(publishAlert).toHaveBeenCalledTimes(1);
        expect(publishAlert.mock.calls[0][0]).toHaveLength(2);
    });
});

describe("handler — write and alert failures are not fatal", () => {
    it("continues saving after one write fails", async () => {
        scanSG.mockResolvedValue([sgFinding]);
        scanS3.mockResolvedValue([s3Finding]);
        scanRDS.mockResolvedValue([]);
        save
            .mockRejectedValueOnce(new Error("throughput exceeded"))
            .mockImplementation(async (f) => ({ ...f, status: "OPEN" }));

        const res = await handler({});
        const body = JSON.parse(res.body);

        expect(save).toHaveBeenCalledTimes(2);
        expect(body.saveErrors).toHaveLength(1);
        expect(body.savedFindings).toBe(1);
        expect(res.statusCode).toBe(207);
    });

    it("does not lose a completed scan when the alert fails", async () => {
        scanSG.mockResolvedValue([sgFinding]);
        scanS3.mockResolvedValue([]);
        scanRDS.mockResolvedValue([]);
        publishAlert.mockRejectedValue(new Error("SNS unavailable"));

        const res = await handler({});
        const body = JSON.parse(res.body);

        // Findings are already persisted; losing the email must not lose the scan.
        expect(body.savedFindings).toBe(1);
        expect(body.alertError).toBe("SNS unavailable");
        expect(res.statusCode).toBe(207);
    });
});

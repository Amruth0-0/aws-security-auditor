import { describe, it, expect } from "vitest";
import { analysePolicyDocument, parsePolicyDocument } from "../../src/scanners/iamRoleScanner.js";

describe("parsePolicyDocument", () => {
    it("parses a plain JSON string", () => {
        const doc = parsePolicyDocument('{"Version":"2012-10-17","Statement":[]}');
        expect(doc.Version).toBe("2012-10-17");
    });

    it("parses a URL-ENCODED document, which is what IAM actually returns", () => {
        const raw = encodeURIComponent('{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}');
        const doc = parsePolicyDocument(raw);
        expect(doc.Statement[0].Action).toBe("*");
    });

    it("passes an already-parsed object straight through", () => {
        const obj = { Statement: [] };
        expect(parsePolicyDocument(obj)).toBe(obj);
    });

    it("returns null for unparseable input instead of throwing", () => {
        expect(parsePolicyDocument("not json at all {{{")).toBeNull();
        expect(parsePolicyDocument(undefined)).toBeNull();
        expect(parsePolicyDocument("")).toBeNull();
    });
});

describe("analysePolicyDocument — what counts as over-permissioned", () => {
    it("flags full administrator access", () => {
        const result = analysePolicyDocument({
            Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }]
        });
        expect(result.admin).toBe(true);
        expect(result.wildcardAction).toBe(true);
        expect(result.wildcardResource).toBe(true);
    });

    it("flags a service-wide wildcard without calling it admin", () => {
        // s3:* on * is broad but not administrator access, and is scored lower.
        const result = analysePolicyDocument({
            Statement: [{ Effect: "Allow", Action: "s3:*", Resource: "*" }]
        });
        expect(result.wildcardAction).toBe(true);
        expect(result.wildcardResource).toBe(true);
        expect(result.admin).toBe(false);
    });

    it("flags a specific action on every resource", () => {
        const result = analysePolicyDocument({
            Statement: [{ Effect: "Allow", Action: "s3:GetObject", Resource: "*" }]
        });
        expect(result.wildcardAction).toBe(false);
        expect(result.wildcardResource).toBe(true);
    });

    it("leaves a properly scoped policy alone", () => {
        const result = analysePolicyDocument({
            Statement: [{
                Effect: "Allow",
                Action: ["s3:GetObject", "s3:PutObject"],
                Resource: "arn:aws:s3:::my-bucket/*"
            }]
        });
        expect(result.wildcardAction).toBe(false);
        expect(result.wildcardResource).toBe(false);
        expect(result.admin).toBe(false);
        expect(result.statements).toEqual([]);
    });

    it("ignores Deny statements", () => {
        // A Deny on "*" is a guardrail, not a risk. Scoring it as one would
        // flag every well-governed account.
        const result = analysePolicyDocument({
            Statement: [{ Effect: "Deny", Action: "*", Resource: "*" }]
        });
        expect(result.wildcardAction).toBe(false);
        expect(result.admin).toBe(false);
    });

    it("handles Statement as a single object rather than an array", () => {
        const result = analysePolicyDocument({
            Statement: { Effect: "Allow", Action: "*", Resource: "*" }
        });
        expect(result.admin).toBe(true);
    });

    it("handles Action and Resource given as arrays", () => {
        const result = analysePolicyDocument({
            Statement: [{
                Effect: "Allow",
                Action: ["ec2:DescribeInstances", "iam:*"],
                Resource: ["arn:aws:s3:::b", "*"]
            }]
        });
        expect(result.wildcardAction).toBe(true);
        expect(result.wildcardResource).toBe(true);
    });

    it("records the offending statements so the alert can name them", () => {
        const result = analysePolicyDocument({
            Statement: [{ Effect: "Allow", Action: "s3:*", Resource: "*" }]
        });
        expect(result.statements).toHaveLength(1);
        expect(result.statements[0].actions).toContain("s3:*");
    });

    it("finds the one bad statement among several good ones", () => {
        const result = analysePolicyDocument({
            Statement: [
                { Effect: "Allow", Action: "s3:GetObject", Resource: "arn:aws:s3:::b/*" },
                { Effect: "Allow", Action: "logs:PutLogEvents", Resource: "arn:aws:logs:::*" },
                { Effect: "Allow", Action: "*", Resource: "*" }
            ]
        });
        expect(result.admin).toBe(true);
        expect(result.statements).toHaveLength(1);
    });

    it("handles null and malformed documents without throwing", () => {
        expect(analysePolicyDocument(null).wildcardAction).toBe(false);
        expect(analysePolicyDocument({}).wildcardAction).toBe(false);
        expect(analysePolicyDocument({ Statement: [null] }).wildcardAction).toBe(false);
    });
});

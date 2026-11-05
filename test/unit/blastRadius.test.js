/**
 * Phase 8 — blast radius scoring tests.
 *
 * These are the cases the Manual specifies for blastRadius.score(finding, iamContext):
 * public + wildcard IAM should be HIGH and NOT auto-remediable; private + scoped
 * should be LOW and auto-remediable.
 */
import { describe, it } from "vitest";

describe("blastRadius.score (Phase 8 — not yet implemented)", () => {
    it.todo("scores a public instance with a wildcard IAM policy as HIGH");
    it.todo("marks HIGH severity findings as autoRemediable: false");
    it.todo("scores a private instance with scoped IAM as LOW");
    it.todo("marks LOW severity findings as autoRemediable: true");
    it.todo("adds points when the resource is tagged sensitive");
    it.todo("respects the configurable HIGH/LOW threshold");
});

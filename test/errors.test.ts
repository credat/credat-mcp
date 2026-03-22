import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import {
	McpAuthErrorCodes,
	authError,
	constraintError,
	scopeError,
} from "../src/errors.js";
import type { AuthErrorPayload } from "../src/types.js";

function parseResult(result: CallToolResult): AuthErrorPayload {
	return JSON.parse((result.content[0] as { type: "text"; text: string }).text);
}

describe("McpAuthErrorCodes", () => {
	it("defines all expected error codes", () => {
		expect(McpAuthErrorCodes.NOT_AUTHENTICATED).toBe("NOT_AUTHENTICATED");
		expect(McpAuthErrorCodes.SESSION_EXPIRED).toBe("SESSION_EXPIRED");
		expect(McpAuthErrorCodes.SESSION_MISMATCH).toBe("SESSION_MISMATCH");
		expect(McpAuthErrorCodes.INSUFFICIENT_SCOPES).toBe("INSUFFICIENT_SCOPES");
		expect(McpAuthErrorCodes.CONSTRAINT_VIOLATION).toBe("CONSTRAINT_VIOLATION");
		expect(McpAuthErrorCodes.CONFIGURATION_ERROR).toBe("CONFIGURATION_ERROR");
	});

	it("contains exactly 6 error codes", () => {
		expect(Object.keys(McpAuthErrorCodes)).toHaveLength(6);
	});
});

describe("authError", () => {
	it("creates a CallToolResult with isError: true", () => {
		const result = authError("Something failed", "SOME_CODE");

		expect(result.isError).toBe(true);
	});

	it("sets content with a single text entry containing valid JSON", () => {
		const result = authError("Something failed", "SOME_CODE");

		expect(result.content).toHaveLength(1);
		expect(result.content[0]).toHaveProperty("type", "text");
		expect(() => parseResult(result)).not.toThrow();
	});

	it("includes error and code in payload", () => {
		const result = authError("Auth failed", McpAuthErrorCodes.NOT_AUTHENTICATED);
		const payload = parseResult(result);

		expect(payload.error).toBe("Auth failed");
		expect(payload.code).toBe("NOT_AUTHENTICATED");
	});

	it("includes details when provided with non-empty array", () => {
		const details = ["detail one", "detail two"];
		const result = authError("Error", "CODE", details);
		const payload = parseResult(result);

		expect(payload.details).toEqual(["detail one", "detail two"]);
	});

	it("omits details key when details is undefined", () => {
		const result = authError("Error", "CODE");
		const payload = parseResult(result);

		expect(payload).not.toHaveProperty("details");
	});

	it("omits details key when details is an empty array", () => {
		const result = authError("Error", "CODE", []);
		const payload = parseResult(result);

		expect(payload).not.toHaveProperty("details");
	});
});

describe("scopeError", () => {
	it("identifies missing scopes correctly", () => {
		const result = scopeError(["read", "write", "admin"], ["read"]);
		const payload = parseResult(result);

		expect(payload.error).toBe("Insufficient scopes. Missing: write, admin");
		expect(payload.code).toBe("INSUFFICIENT_SCOPES");
		expect(payload.details).toEqual([
			"required: read, write, admin",
			"granted: read",
		]);
	});

	it("reports all scopes as missing when none are granted", () => {
		const result = scopeError(["read", "write"], []);
		const payload = parseResult(result);

		expect(payload.error).toBe("Insufficient scopes. Missing: read, write");
		expect(payload.details).toEqual([
			"required: read, write",
			"granted: ",
		]);
	});

	it("reports no missing scopes when all are present", () => {
		const result = scopeError(["read", "write"], ["read", "write"]);
		const payload = parseResult(result);

		expect(payload.error).toBe("Insufficient scopes. Missing: ");
		expect(payload.details).toEqual([
			"required: read, write",
			"granted: read, write",
		]);
	});

	it("handles single required scope missing", () => {
		const result = scopeError(["admin"], ["read", "write"]);
		const payload = parseResult(result);

		expect(payload.error).toBe("Insufficient scopes. Missing: admin");
	});

	it("always sets isError to true", () => {
		const result = scopeError(["read"], []);

		expect(result.isError).toBe(true);
	});
});

describe("constraintError", () => {
	it("formats a single violation", () => {
		const result = constraintError([
			{ constraint: "maxAmount", message: "Exceeds maximum transaction value of 1000" },
		]);
		const payload = parseResult(result);

		expect(payload.error).toBe("Constraint violation: Exceeds maximum transaction value of 1000");
		expect(payload.code).toBe("CONSTRAINT_VIOLATION");
		expect(payload.details).toEqual([
			"maxAmount: Exceeds maximum transaction value of 1000",
		]);
	});

	it("formats multiple violations separated by semicolons", () => {
		const result = constraintError([
			{ constraint: "maxAmount", message: "Amount too high" },
			{ constraint: "allowedDomain", message: "Domain not permitted" },
		]);
		const payload = parseResult(result);

		expect(payload.error).toBe("Constraint violation: Amount too high; Domain not permitted");
		expect(payload.details).toEqual([
			"maxAmount: Amount too high",
			"allowedDomain: Domain not permitted",
		]);
	});

	it("always sets isError to true", () => {
		const result = constraintError([
			{ constraint: "test", message: "fail" },
		]);

		expect(result.isError).toBe(true);
	});

	it("produces parseable JSON matching AuthErrorPayload shape", () => {
		const result = constraintError([
			{ constraint: "rate", message: "Rate limit exceeded" },
			{ constraint: "ip", message: "IP blocked" },
			{ constraint: "time", message: "Outside allowed hours" },
		]);
		const payload = parseResult(result);

		expect(typeof payload.error).toBe("string");
		expect(typeof payload.code).toBe("string");
		expect(Array.isArray(payload.details)).toBe(true);
		expect(payload.details).toHaveLength(3);
	});
});

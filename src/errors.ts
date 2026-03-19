import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { AuthErrorPayload, ConstraintViolation } from "./types.js";

// ── Error Codes ──

export const McpAuthErrorCodes = {
	NOT_AUTHENTICATED: "NOT_AUTHENTICATED",
	SESSION_EXPIRED: "SESSION_EXPIRED",
	SESSION_MISMATCH: "SESSION_MISMATCH",
	INSUFFICIENT_SCOPES: "INSUFFICIENT_SCOPES",
	CONSTRAINT_VIOLATION: "CONSTRAINT_VIOLATION",
	CONFIGURATION_ERROR: "CONFIGURATION_ERROR",
} as const;

export type McpAuthErrorCode =
	(typeof McpAuthErrorCodes)[keyof typeof McpAuthErrorCodes];

// ── Error Response Builders ──

export function authError(
	message: string,
	code: string,
	details?: string[],
): CallToolResult {
	const payload: AuthErrorPayload = { error: message, code };
	if (details && details.length > 0) {
		payload.details = details;
	}
	return {
		content: [{ type: "text", text: JSON.stringify(payload) }],
		isError: true,
	};
}

export function scopeError(
	required: string[],
	actual: string[],
): CallToolResult {
	const missing = required.filter((s) => !actual.includes(s));
	return authError(
		`Insufficient scopes. Missing: ${missing.join(", ")}`,
		McpAuthErrorCodes.INSUFFICIENT_SCOPES,
		[`required: ${required.join(", ")}`, `granted: ${actual.join(", ")}`],
	);
}

export function constraintError(
	violations: ConstraintViolation[],
): CallToolResult {
	return authError(
		`Constraint violation: ${violations.map((v) => v.message).join("; ")}`,
		McpAuthErrorCodes.CONSTRAINT_VIOLATION,
		violations.map((v) => `${v.constraint}: ${v.message}`),
	);
}

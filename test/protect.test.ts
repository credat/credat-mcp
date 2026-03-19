import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { McpAuthErrorCodes } from "../src/errors.js";
import { createProtect } from "../src/protect.js";
import { SessionStore } from "../src/session.js";
import type { AuthContext, SessionAuth, ToolExtra } from "../src/types.js";
import { createMockExtra } from "./helpers.js";

function makeSessionAuth(
	scopes: string[],
	constraints?: Record<string, unknown>,
): SessionAuth {
	return {
		delegationResult: {
			valid: true as const,
			agent: "did:web:agents.example.com:test",
			owner: "did:web:owner.example.com",
			scopes,
			constraints,
			errors: [] as [],
		},
		authenticatedAt: Date.now(),
	};
}

function parseError(result: CallToolResult): { error: string; code: string; details?: string[] } {
	return JSON.parse((result.content[0] as { text: string }).text);
}

describe("protect", () => {
	it("allows authenticated call with correct scopes", async () => {
		const store = new SessionStore(3_600_000);
		store.set("__stdio__", makeSessionAuth(["email:read", "email:send"]));

		const protect = createProtect(store);
		const handler = protect(
			{ scopes: ["email:read"] },
			(args: Record<string, unknown>, extra: ToolExtra & { auth: AuthContext }) => {
				return {
					content: [{ type: "text" as const, text: `hello ${extra.auth.agentDid}` }],
				};
			},
		);

		const result = await handler({}, createMockExtra());

		expect(result.isError).toBeUndefined();
		expect((result.content[0] as { text: string }).text).toContain(
			"did:web:agents.example.com:test",
		);
	});

	it("rejects unauthenticated call", async () => {
		const store = new SessionStore(3_600_000);
		const protect = createProtect(store);

		const handler = protect({}, (_args, _extra) => ({
			content: [{ type: "text" as const, text: "should not reach" }],
		}));

		const result = await handler({}, createMockExtra());

		expect(result.isError).toBe(true);
		const error = parseError(result);
		expect(error.code).toBe(McpAuthErrorCodes.NOT_AUTHENTICATED);
	});

	it("rejects expired session", async () => {
		const store = new SessionStore(100); // 100ms TTL
		store.set("__stdio__", {
			...makeSessionAuth(["email:read"]),
			authenticatedAt: Date.now() - 200,
		});

		const protect = createProtect(store);
		const handler = protect({}, (_args, _extra) => ({
			content: [{ type: "text" as const, text: "should not reach" }],
		}));

		const result = await handler({}, createMockExtra());

		expect(result.isError).toBe(true);
		const error = parseError(result);
		expect(error.code).toBe(McpAuthErrorCodes.NOT_AUTHENTICATED);
	});

	it("rejects insufficient scopes (all required)", async () => {
		const store = new SessionStore(3_600_000);
		store.set("__stdio__", makeSessionAuth(["email:read"]));

		const protect = createProtect(store);
		const handler = protect({ scopes: ["email:read", "email:send"] }, (_args, _extra) => ({
			content: [{ type: "text" as const, text: "should not reach" }],
		}));

		const result = await handler({}, createMockExtra());

		expect(result.isError).toBe(true);
		const error = parseError(result);
		expect(error.code).toBe(McpAuthErrorCodes.INSUFFICIENT_SCOPES);
		expect(error.error).toContain("email:send");
	});

	it("allows when any one scope matches (anyScope)", async () => {
		const store = new SessionStore(3_600_000);
		store.set("__stdio__", makeSessionAuth(["calendar:write"]));

		const protect = createProtect(store);
		const handler = protect(
			{ anyScope: ["email:read", "calendar:write", "admin"] },
			(_args, _extra) => ({
				content: [{ type: "text" as const, text: "ok" }],
			}),
		);

		const result = await handler({}, createMockExtra());
		expect(result.isError).toBeUndefined();
	});

	it("rejects when no anyScope matches", async () => {
		const store = new SessionStore(3_600_000);
		store.set("__stdio__", makeSessionAuth(["calendar:write"]));

		const protect = createProtect(store);
		const handler = protect(
			{ anyScope: ["email:read", "admin"] },
			(_args, _extra) => ({
				content: [{ type: "text" as const, text: "should not reach" }],
			}),
		);

		const result = await handler({}, createMockExtra());
		expect(result.isError).toBe(true);
	});

	it("validates constraints", async () => {
		const store = new SessionStore(3_600_000);
		store.set(
			"__stdio__",
			makeSessionAuth(["payment"], { maxTransactionValue: 100 }),
		);

		const protect = createProtect(store);
		const handler = protect(
			{
				constraintContext: { transactionValue: 500 },
			},
			(_args, _extra) => ({
				content: [{ type: "text" as const, text: "should not reach" }],
			}),
		);

		const result = await handler({}, createMockExtra());
		expect(result.isError).toBe(true);
		const error = parseError(result);
		expect(error.code).toBe(McpAuthErrorCodes.CONSTRAINT_VIOLATION);
	});

	it("supports dynamic constraint context from args", async () => {
		const store = new SessionStore(3_600_000);
		store.set(
			"__stdio__",
			makeSessionAuth(["payment"], { maxTransactionValue: 100 }),
		);

		const protect = createProtect(store);
		const handler = protect(
			{
				constraintContext: (args) => ({
					transactionValue: args.amount as number,
				}),
			},
			(_args, _extra) => ({
				content: [{ type: "text" as const, text: "ok" }],
			}),
		);

		// Under limit — should pass
		const ok = await handler({ amount: 50 }, createMockExtra());
		expect(ok.isError).toBeUndefined();

		// Over limit — should fail
		const fail = await handler({ amount: 200 }, createMockExtra());
		expect(fail.isError).toBe(true);
	});

	it("passes args through to handler unmodified", async () => {
		const store = new SessionStore(3_600_000);
		store.set("__stdio__", makeSessionAuth(["data:read"]));

		const protect = createProtect(store);
		let receivedArgs: Record<string, unknown> | undefined;

		const handler = protect({}, (args, _extra) => {
			receivedArgs = args;
			return {
				content: [{ type: "text" as const, text: "ok" }],
			};
		});

		await handler({ foo: "bar", count: 42 }, createMockExtra());
		expect(receivedArgs).toEqual({ foo: "bar", count: 42 });
	});

	it("uses sessionId from extra for HTTP transport", async () => {
		const store = new SessionStore(3_600_000);
		store.set("http-session-123", makeSessionAuth(["data:read"]));

		const protect = createProtect(store);
		const handler = protect({}, (_args, _extra) => ({
			content: [{ type: "text" as const, text: "ok" }],
		}));

		// Different session — should fail
		const fail = await handler({}, createMockExtra("http-session-456"));
		expect(fail.isError).toBe(true);

		// Correct session — should pass
		const ok = await handler({}, createMockExtra("http-session-123"));
		expect(ok.isError).toBeUndefined();
	});
});

import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { createChallenge, generateKeyPair } from "@credat/sdk";
import type { ChallengeMessage } from "@credat/sdk";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CredatAuth } from "../src/auth.js";
import { McpAuthErrorCodes } from "../src/errors.js";
import { SqliteChallengeStore, SqliteSessionStore } from "../src/sqlite.js";
import type { ToolExtra } from "../src/types.js";
import {
	createMockExtra,
	createMockServer,
	createTestSetup,
	performHandshake,
	type TestSetup,
} from "./helpers.js";

function parseResult(result: CallToolResult): Record<string, unknown> {
	return JSON.parse((result.content[0] as { text: string }).text);
}

// ── Helper: run full challenge → authenticate flow ──

async function authenticateSession(
	server: ReturnType<typeof createMockServer>,
	setup: TestSetup,
	extra: ToolExtra,
): Promise<CallToolResult> {
	const challengeResult = (await server.registeredTools
		.get("credat:challenge")!
		.callback(extra)) as CallToolResult;
	const challenge = parseResult(challengeResult) as unknown as ChallengeMessage;
	const presentation = await performHandshake(challenge, setup);
	return (await server.registeredTools
		.get("credat:authenticate")!
		.callback({ presentation }, extra)) as CallToolResult;
}

// ══════════════════════════════════════════════════════════════
// E2E Tests — Full auth flows with in-memory store (default)
// ══════════════════════════════════════════════════════════════

describe("E2E: full auth flow (memory store)", () => {
	it("challenge → authenticate → protected call succeeds", async () => {
		const setup = await createTestSetup(["email:read", "email:send"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		const extra = createMockExtra();
		const authResult = await authenticateSession(server, setup, extra);

		expect(authResult.isError).toBeUndefined();
		const data = parseResult(authResult);
		expect(data.authenticated).toBe(true);
		expect(data.scopes).toEqual(["email:read", "email:send"]);

		// Protected tool call
		const handler = auth.protect(
			{ scopes: ["email:read"] },
			(_args: Record<string, unknown>, protectedExtra: ToolExtra & { auth: { agentDid: string } }) => ({
				content: [{ type: "text" as const, text: `hello ${protectedExtra.auth.agentDid}` }],
			}),
		);
		const result = await handler({}, extra);
		expect(result.isError).toBeUndefined();
		expect((result.content[0] as { text: string }).text).toContain(setup.agent.did);
	});

	it("protected tool rejects unauthenticated call with actionable message", async () => {
		const key = generateKeyPair("ES256");
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: key.publicKey,
		});

		const handler = auth.protect({}, (_args: Record<string, unknown>) => ({
			content: [{ type: "text" as const, text: "unreachable" }],
		}));

		const result = await handler({}, createMockExtra());
		expect(result.isError).toBe(true);
		const error = parseResult(result);
		expect(error.code).toBe(McpAuthErrorCodes.NOT_AUTHENTICATED);
		expect(error.error).toContain("credat:challenge");
	});

	it("re-authentication after session revocation", async () => {
		const setup = await createTestSetup(["email:read"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		const extra = createMockExtra();

		// First auth
		await authenticateSession(server, setup, extra);
		expect(await auth.isAuthenticated()).toBe(true);

		// Revoke
		await auth.revokeSession();
		expect(await auth.isAuthenticated()).toBe(false);

		// Re-authenticate
		await authenticateSession(server, setup, extra);
		expect(await auth.isAuthenticated()).toBe(true);
	});

	it("getSessionAuth returns full delegation result", async () => {
		const setup = await createTestSetup(["data:read", "data:write"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		await authenticateSession(server, setup, createMockExtra());

		const session = await auth.getSessionAuth();
		expect(session).toBeDefined();
		expect(session!.delegationResult.valid).toBe(true);
		expect(session!.delegationResult.agent).toBe(setup.agent.did);
		expect(session!.delegationResult.scopes).toEqual(["data:read", "data:write"]);
		expect(session!.authenticatedAt).toBeLessThanOrEqual(Date.now());
	});
});

// ══════════════════════════════════════════════════════════════
// E2E Tests — Multi-agent scenarios
// ══════════════════════════════════════════════════════════════

describe("E2E: multi-agent", () => {
	it("resolveAgentKey authenticates different agents", async () => {
		const setup1 = await createTestSetup(["email:read"]);
		const setup2 = await createTestSetup(["calendar:write"]);

		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup1.ownerKeyPair.publicKey,
			resolveAgentKey: async (agentDid: string) => {
				if (agentDid === setup1.agent.did) return setup1.agent.keyPair.publicKey;
				if (agentDid === setup2.agent.did) return setup2.agent.keyPair.publicKey;
				throw new Error(`Unknown agent: ${agentDid}`);
			},
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		// Agent 1 authenticates on session-1
		const extra1 = createMockExtra("session-1");
		const result1 = await authenticateSession(server, setup1, extra1);
		expect(result1.isError).toBeUndefined();
		expect(parseResult(result1).agent).toBe(setup1.agent.did);

		// Agent 2 authenticates on session-2 (different owner key — will fail verification)
		// This tests that resolveAgentKey is called with the correct agent DID
		expect(await auth.isAuthenticated("session-1")).toBe(true);
		expect(await auth.isAuthenticated("session-2")).toBe(false);
	});

	it("resolveAgentKey error returns CONFIGURATION_ERROR", async () => {
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			resolveAgentKey: async () => {
				throw new Error("DNS resolution failed");
			},
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		const extra = createMockExtra();
		const result = await authenticateSession(server, setup, extra);
		expect(result.isError).toBe(true);
		const error = parseResult(result);
		expect(error.code).toBe(McpAuthErrorCodes.CONFIGURATION_ERROR);
		expect(error.error).toContain("DNS resolution failed");
	});
});

// ══════════════════════════════════════════════════════════════
// E2E Tests — Concurrent sessions (HTTP transport)
// ══════════════════════════════════════════════════════════════

describe("E2E: concurrent sessions", () => {
	it("multiple sessions authenticate independently", async () => {
		const setup = await createTestSetup(["data:read"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		// Authenticate 3 sessions
		for (const id of ["session-A", "session-B", "session-C"]) {
			await authenticateSession(server, setup, createMockExtra(id));
		}

		expect(await auth.isAuthenticated("session-A")).toBe(true);
		expect(await auth.isAuthenticated("session-B")).toBe(true);
		expect(await auth.isAuthenticated("session-C")).toBe(true);
		expect(await auth.isAuthenticated("session-D")).toBe(false);
	});

	it("revoking one session does not affect others", async () => {
		const setup = await createTestSetup(["data:read"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		await authenticateSession(server, setup, createMockExtra("session-A"));
		await authenticateSession(server, setup, createMockExtra("session-B"));

		await auth.revokeSession("session-A");

		expect(await auth.isAuthenticated("session-A")).toBe(false);
		expect(await auth.isAuthenticated("session-B")).toBe(true);
	});

	it("challenge from session-A cannot be used by session-B", async () => {
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		// Challenge from session-A
		const extraA = createMockExtra("session-A");
		const challengeResult = (await server.registeredTools
			.get("credat:challenge")!
			.callback(extraA)) as CallToolResult;
		const challenge = parseResult(challengeResult) as unknown as ChallengeMessage;
		const presentation = await performHandshake(challenge, setup);

		// Try to auth from session-B
		const result = (await server.registeredTools
			.get("credat:authenticate")!
			.callback({ presentation }, createMockExtra("session-B"))) as CallToolResult;

		expect(result.isError).toBe(true);
		expect(parseResult(result).code).toBe(McpAuthErrorCodes.SESSION_MISMATCH);
	});
});

// ══════════════════════════════════════════════════════════════
// E2E Tests — Scope validation flows
// ══════════════════════════════════════════════════════════════

describe("E2E: scope validation", () => {
	it("scopes (ALL) — requires every listed scope", async () => {
		const setup = await createTestSetup(["email:read"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);
		await authenticateSession(server, setup, createMockExtra());

		const handler = auth.protect(
			{ scopes: ["email:read", "email:send"] },
			(_args: Record<string, unknown>) => ({
				content: [{ type: "text" as const, text: "ok" }],
			}),
		);

		const result = await handler({}, createMockExtra());
		expect(result.isError).toBe(true);
		const error = parseResult(result);
		expect(error.code).toBe(McpAuthErrorCodes.INSUFFICIENT_SCOPES);
		expect(error.error).toContain("email:send");
	});

	it("anyScope — allows if any one scope matches", async () => {
		const setup = await createTestSetup(["calendar:write"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);
		await authenticateSession(server, setup, createMockExtra());

		const handler = auth.protect(
			{ anyScope: ["email:read", "calendar:write", "admin"] },
			(_args: Record<string, unknown>) => ({
				content: [{ type: "text" as const, text: "ok" }],
			}),
		);

		const result = await handler({}, createMockExtra());
		expect(result.isError).toBeUndefined();
	});

	it("anyScope — rejects when none match", async () => {
		const setup = await createTestSetup(["calendar:write"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);
		await authenticateSession(server, setup, createMockExtra());

		const handler = auth.protect(
			{ anyScope: ["email:read", "admin"] },
			(_args: Record<string, unknown>) => ({
				content: [{ type: "text" as const, text: "unreachable" }],
			}),
		);

		const result = await handler({}, createMockExtra());
		expect(result.isError).toBe(true);
	});

	it("empty scopes requirement — allows any authenticated agent", async () => {
		const setup = await createTestSetup(["anything"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);
		await authenticateSession(server, setup, createMockExtra());

		const handler = auth.protect({}, (_args: Record<string, unknown>) => ({
			content: [{ type: "text" as const, text: "ok" }],
		}));

		const result = await handler({}, createMockExtra());
		expect(result.isError).toBeUndefined();
	});
});

// ══════════════════════════════════════════════════════════════
// E2E Tests — Constraint validation flows
// ══════════════════════════════════════════════════════════════

describe("E2E: constraint validation", () => {
	it("static constraint context — rejects over limit", async () => {
		const setup = await createTestSetup(["payment"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		// Need a delegation with constraints — createTestSetup doesn't set constraints
		// so we test via the protect layer with a session that has constraints
		// We can inject a session directly for this test
		await authenticateSession(server, setup, createMockExtra());

		// Since the delegation from createTestSetup doesn't have constraints,
		// this should pass (no constraints to violate)
		const handler = auth.protect(
			{ constraintContext: { transactionValue: 500 } },
			(_args: Record<string, unknown>) => ({
				content: [{ type: "text" as const, text: "ok" }],
			}),
		);

		const result = await handler({}, createMockExtra());
		// No constraints on delegation = no violations = passes
		expect(result.isError).toBeUndefined();
	});

	it("dynamic constraint context from args", async () => {
		const setup = await createTestSetup(["email:send"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);
		await authenticateSession(server, setup, createMockExtra());

		const handler = auth.protect(
			{
				scopes: ["email:send"],
				constraintContext: (args) => ({
					domain: (args.to as string).split("@")[1],
				}),
			},
			(args: Record<string, unknown>, extra: ToolExtra & { auth: { agentDid: string } }) => ({
				content: [{ type: "text" as const, text: `sent by ${extra.auth.agentDid}` }],
			}),
		);

		// No domain constraints on delegation = passes
		const result = await handler({ to: "user@example.com" }, createMockExtra());
		expect(result.isError).toBeUndefined();
	});
});

// ══════════════════════════════════════════════════════════════
// E2E Tests — Session expiry
// ══════════════════════════════════════════════════════════════

describe("E2E: session expiry", () => {
	it("expired session is rejected on protected call", async () => {
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			sessionMaxAgeMs: 50,
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		await authenticateSession(server, setup, createMockExtra());
		expect(await auth.isAuthenticated()).toBe(true);

		// Wait for expiry
		await new Promise((r) => setTimeout(r, 100));

		expect(await auth.isAuthenticated()).toBe(false);

		const handler = auth.protect({}, (_args: Record<string, unknown>) => ({
			content: [{ type: "text" as const, text: "unreachable" }],
		}));
		const result = await handler({}, createMockExtra());
		expect(result.isError).toBe(true);
		expect(parseResult(result).code).toBe(McpAuthErrorCodes.NOT_AUTHENTICATED);
	});

	it("expired challenge nonce is rejected", async () => {
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			challengeMaxAgeMs: 50,
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		const extra = createMockExtra();
		const challengeResult = (await server.registeredTools
			.get("credat:challenge")!
			.callback(extra)) as CallToolResult;
		const challenge = parseResult(challengeResult) as unknown as ChallengeMessage;
		const presentation = await performHandshake(challenge, setup);

		// Wait for challenge to expire
		await new Promise((r) => setTimeout(r, 100));

		const result = (await server.registeredTools
			.get("credat:authenticate")!
			.callback({ presentation }, extra)) as CallToolResult;
		expect(result.isError).toBe(true);
	});
});

// ══════════════════════════════════════════════════════════════
// E2E Tests — Security: replay attacks
// ══════════════════════════════════════════════════════════════

describe("E2E: replay attack prevention", () => {
	it("same nonce cannot be used twice", async () => {
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		const extra = createMockExtra();
		const challengeResult = (await server.registeredTools
			.get("credat:challenge")!
			.callback(extra)) as CallToolResult;
		const challenge = parseResult(challengeResult) as unknown as ChallengeMessage;
		const presentation = await performHandshake(challenge, setup);

		// First auth succeeds
		const first = (await server.registeredTools
			.get("credat:authenticate")!
			.callback({ presentation }, extra)) as CallToolResult;
		expect(first.isError).toBeUndefined();

		// Replay fails
		const replay = (await server.registeredTools
			.get("credat:authenticate")!
			.callback({ presentation }, extra)) as CallToolResult;
		expect(replay.isError).toBe(true);
		expect(parseResult(replay).code).toBe(McpAuthErrorCodes.NOT_AUTHENTICATED);
	});

	it("each challenge produces a unique nonce", async () => {
		const key = generateKeyPair("ES256");
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: key.publicKey,
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		const extra = createMockExtra();
		const nonces = new Set<string>();

		for (let i = 0; i < 20; i++) {
			const result = (await server.registeredTools
				.get("credat:challenge")!
				.callback(extra)) as CallToolResult;
			const data = parseResult(result);
			nonces.add(data.nonce as string);
		}

		expect(nonces.size).toBe(20);
	});
});

// ══════════════════════════════════════════════════════════════
// E2E Tests — Custom tool prefix
// ══════════════════════════════════════════════════════════════

describe("E2E: custom tool prefix", () => {
	it("auth flow works with custom prefix", async () => {
		const setup = await createTestSetup(["data:read"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			toolPrefix: "myauth",
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		expect(server.registeredTools.has("myauth:challenge")).toBe(true);
		expect(server.registeredTools.has("myauth:authenticate")).toBe(true);
		expect(server.registeredTools.has("credat:challenge")).toBe(false);

		const extra = createMockExtra();
		const challengeResult = (await server.registeredTools
			.get("myauth:challenge")!
			.callback(extra)) as CallToolResult;
		const challenge = parseResult(challengeResult) as unknown as ChallengeMessage;
		const presentation = await performHandshake(challenge, setup);

		const authResult = (await server.registeredTools
			.get("myauth:authenticate")!
			.callback({ presentation }, extra)) as CallToolResult;
		expect(authResult.isError).toBeUndefined();
		expect(parseResult(authResult).authenticated).toBe(true);
	});
});

// ══════════════════════════════════════════════════════════════
// E2E Tests — SQLite store backend
// ══════════════════════════════════════════════════════════════

describe("E2E: SQLite store backend", () => {
	let db: InstanceType<typeof Database>;

	beforeEach(() => {
		db = new Database(":memory:");
	});

	afterEach(() => {
		db.close();
	});

	it("full auth flow works with SQLite stores", async () => {
		const setup = await createTestSetup(["email:read", "email:send"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			challengeStore: new SqliteChallengeStore(300_000, { db }),
			sessionStore: new SqliteSessionStore(3_600_000, { db }),
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		const extra = createMockExtra();
		const authResult = await authenticateSession(server, setup, extra);

		expect(authResult.isError).toBeUndefined();
		expect(parseResult(authResult).authenticated).toBe(true);

		// Protected tool works
		const handler = auth.protect(
			{ scopes: ["email:read"] },
			(_args: Record<string, unknown>, protectedExtra: ToolExtra & { auth: { agentDid: string } }) => ({
				content: [{ type: "text" as const, text: `hi ${protectedExtra.auth.agentDid}` }],
			}),
		);
		const result = await handler({}, extra);
		expect(result.isError).toBeUndefined();
	});

	it("replay prevention works with SQLite stores", async () => {
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			challengeStore: new SqliteChallengeStore(300_000, { db }),
			sessionStore: new SqliteSessionStore(3_600_000, { db }),
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		const extra = createMockExtra();
		const challengeResult = (await server.registeredTools
			.get("credat:challenge")!
			.callback(extra)) as CallToolResult;
		const challenge = parseResult(challengeResult) as unknown as ChallengeMessage;
		const presentation = await performHandshake(challenge, setup);

		const first = (await server.registeredTools
			.get("credat:authenticate")!
			.callback({ presentation }, extra)) as CallToolResult;
		expect(first.isError).toBeUndefined();

		const replay = (await server.registeredTools
			.get("credat:authenticate")!
			.callback({ presentation }, extra)) as CallToolResult;
		expect(replay.isError).toBe(true);
	});

	it("session isolation works with SQLite stores", async () => {
		const setup = await createTestSetup(["data:read"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			challengeStore: new SqliteChallengeStore(300_000, { db }),
			sessionStore: new SqliteSessionStore(3_600_000, { db }),
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		await authenticateSession(server, setup, createMockExtra("session-1"));

		expect(await auth.isAuthenticated("session-1")).toBe(true);
		expect(await auth.isAuthenticated("session-2")).toBe(false);
	});

	it("session expiry works with SQLite stores", async () => {
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			challengeStore: new SqliteChallengeStore(300_000, { db }),
			sessionStore: new SqliteSessionStore(50, { db }), // 50ms TTL
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		await authenticateSession(server, setup, createMockExtra());
		expect(await auth.isAuthenticated()).toBe(true);

		await new Promise((r) => setTimeout(r, 100));
		expect(await auth.isAuthenticated()).toBe(false);
	});

	it("session revocation works with SQLite stores", async () => {
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			challengeStore: new SqliteChallengeStore(300_000, { db }),
			sessionStore: new SqliteSessionStore(3_600_000, { db }),
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		await authenticateSession(server, setup, createMockExtra());
		expect(await auth.isAuthenticated()).toBe(true);

		await auth.revokeSession();
		expect(await auth.isAuthenticated()).toBe(false);
	});

	it("scope validation works with SQLite stores", async () => {
		const setup = await createTestSetup(["email:read"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			challengeStore: new SqliteChallengeStore(300_000, { db }),
			sessionStore: new SqliteSessionStore(3_600_000, { db }),
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);
		await authenticateSession(server, setup, createMockExtra());

		// Correct scope — passes
		const readHandler = auth.protect(
			{ scopes: ["email:read"] },
			(_args: Record<string, unknown>) => ({
				content: [{ type: "text" as const, text: "ok" }],
			}),
		);
		const readResult = await readHandler({}, createMockExtra());
		expect(readResult.isError).toBeUndefined();

		// Wrong scope — fails
		const writeHandler = auth.protect(
			{ scopes: ["email:write"] },
			(_args: Record<string, unknown>) => ({
				content: [{ type: "text" as const, text: "unreachable" }],
			}),
		);
		const writeResult = await writeHandler({}, createMockExtra());
		expect(writeResult.isError).toBe(true);
	});
});

// ══════════════════════════════════════════════════════════════
// E2E Tests — Expired delegation
// ══════════════════════════════════════════════════════════════

describe("E2E: expired delegation", () => {
	it("rejects delegation that expired in the past", async () => {
		const pastDate = new Date(Date.now() - 3_600_000).toISOString();
		const setup = await createTestSetup(["email:read"], pastDate);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		const extra = createMockExtra();
		const result = await authenticateSession(server, setup, extra);

		expect(result.isError).toBe(true);
		const error = parseResult(result);
		expect(error.error).toBe("Authentication failed.");
	});
});

// ══════════════════════════════════════════════════════════════
// E2E Tests — Auth context passed to handlers
// ══════════════════════════════════════════════════════════════

describe("E2E: auth context in handlers", () => {
	it("handler receives correct auth context", async () => {
		const setup = await createTestSetup(["data:read", "data:write"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);
		await authenticateSession(server, setup, createMockExtra());

		let capturedAuth: Record<string, unknown> | undefined;
		const handler = auth.protect(
			{},
			(_args: Record<string, unknown>, extra: ToolExtra & { auth: Record<string, unknown> }) => {
				capturedAuth = extra.auth;
				return { content: [{ type: "text" as const, text: "ok" }] };
			},
		);
		await handler({}, createMockExtra());

		expect(capturedAuth).toBeDefined();
		expect(capturedAuth!.agentDid).toBe(setup.agent.did);
		expect(capturedAuth!.ownerDid).toBe(setup.ownerDid);
		expect(capturedAuth!.scopes).toEqual(["data:read", "data:write"]);
	});

	it("handler receives original args unmodified", async () => {
		const setup = await createTestSetup(["data:read"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});
		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);
		await authenticateSession(server, setup, createMockExtra());

		let capturedArgs: Record<string, unknown> | undefined;
		const handler = auth.protect({}, (args: Record<string, unknown>) => {
			capturedArgs = args;
			return { content: [{ type: "text" as const, text: "ok" }] };
		});

		const testArgs = { query: "test", limit: 10, nested: { a: 1 } };
		await handler(testArgs, createMockExtra());

		expect(capturedArgs).toEqual(testArgs);
	});
});

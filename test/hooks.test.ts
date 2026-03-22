import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { generateKeyPair } from "@credat/sdk";
import type { ChallengeMessage } from "@credat/sdk";
import { describe, expect, it, vi } from "vitest";
import { CredatAuth } from "../src/auth.js";
import { McpAuthErrorCodes } from "../src/errors.js";
import { createProtect } from "../src/protect.js";
import { SessionStore } from "../src/session.js";
import type {
	AccessDeniedEvent,
	AuthenticatedEvent,
	AuthFailedEvent,
	ChallengeEvent,
	CredatAuthHooks,
	SessionRevokedEvent,
	ToolExtra,
} from "../src/types.js";
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
// onChallenge
// ══════════════════════════════════════════════════════════════

describe("hooks: onChallenge", () => {
	it("fires when a challenge is issued", async () => {
		const onChallenge = vi.fn<(event: ChallengeEvent) => void>();
		const key = generateKeyPair("ES256");
		const auth = new CredatAuth({
			serverDid: "did:web:test.example.com",
			ownerPublicKey: key.publicKey,
			hooks: { onChallenge },
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		const extra = createMockExtra();
		await server.registeredTools.get("credat:challenge")!.callback(extra);

		expect(onChallenge).toHaveBeenCalledOnce();
		const event = onChallenge.mock.calls[0][0];
		expect(event.sessionId).toBe("__stdio__");
		expect(event.nonce).toBeDefined();
		expect(event.timestamp).toBeLessThanOrEqual(Date.now());
	});

	it("includes correct sessionId for HTTP transport", async () => {
		const onChallenge = vi.fn<(event: ChallengeEvent) => void>();
		const key = generateKeyPair("ES256");
		const auth = new CredatAuth({
			serverDid: "did:web:test.example.com",
			ownerPublicKey: key.publicKey,
			hooks: { onChallenge },
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		await server.registeredTools.get("credat:challenge")!.callback(createMockExtra("http-123"));

		expect(onChallenge.mock.calls[0][0].sessionId).toBe("http-123");
	});

	it("fires for each challenge issued", async () => {
		const onChallenge = vi.fn<(event: ChallengeEvent) => void>();
		const key = generateKeyPair("ES256");
		const auth = new CredatAuth({
			serverDid: "did:web:test.example.com",
			ownerPublicKey: key.publicKey,
			hooks: { onChallenge },
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		for (let i = 0; i < 3; i++) {
			await server.registeredTools.get("credat:challenge")!.callback(createMockExtra());
		}

		expect(onChallenge).toHaveBeenCalledTimes(3);
		// Each nonce should be unique
		const nonces = onChallenge.mock.calls.map((c) => c[0].nonce);
		expect(new Set(nonces).size).toBe(3);
	});
});

// ══════════════════════════════════════════════════════════════
// onAuthenticated
// ══════════════════════════════════════════════════════════════

describe("hooks: onAuthenticated", () => {
	it("fires on successful authentication", async () => {
		const onAuthenticated = vi.fn<(event: AuthenticatedEvent) => void>();
		const setup = await createTestSetup(["email:read", "email:send"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			hooks: { onAuthenticated },
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		const extra = createMockExtra();
		await authenticateSession(server, setup, extra);

		expect(onAuthenticated).toHaveBeenCalledOnce();
		const event = onAuthenticated.mock.calls[0][0];
		expect(event.sessionId).toBe("__stdio__");
		expect(event.agentDid).toBe(setup.agent.did);
		expect(event.ownerDid).toBe(setup.ownerDid);
		expect(event.scopes).toEqual(["email:read", "email:send"]);
		expect(event.timestamp).toBeLessThanOrEqual(Date.now());
	});

	it("does not fire on failed authentication", async () => {
		const onAuthenticated = vi.fn<(event: AuthenticatedEvent) => void>();
		const pastDate = new Date(Date.now() - 3_600_000).toISOString();
		const setup = await createTestSetup(["email:read"], pastDate);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			hooks: { onAuthenticated },
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		await authenticateSession(server, setup, createMockExtra());

		expect(onAuthenticated).not.toHaveBeenCalled();
	});
});

// ══════════════════════════════════════════════════════════════
// onAuthFailed
// ══════════════════════════════════════════════════════════════

describe("hooks: onAuthFailed", () => {
	it("fires on unknown/expired nonce", async () => {
		const onAuthFailed = vi.fn<(event: AuthFailedEvent) => void>();
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			hooks: { onAuthFailed },
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		// Authenticate with a fake presentation (unknown nonce)
		const fakePresentation = {
			type: "credat:presentation" as const,
			delegation: "fake",
			nonce: "nonexistent-nonce",
			proof: "fake",
			from: "did:web:agents.example.com:fake",
		};

		await server.registeredTools
			.get("credat:authenticate")!
			.callback({ presentation: fakePresentation }, createMockExtra());

		expect(onAuthFailed).toHaveBeenCalledOnce();
		const event = onAuthFailed.mock.calls[0][0];
		expect(event.code).toBe(McpAuthErrorCodes.NOT_AUTHENTICATED);
		expect(event.reason).toContain("nonce");
		expect(event.agentDid).toBe("did:web:agents.example.com:fake");
	});

	it("fires on session mismatch", async () => {
		const onAuthFailed = vi.fn<(event: AuthFailedEvent) => void>();
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			hooks: { onAuthFailed },
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		// Challenge from session-A
		const challengeResult = (await server.registeredTools
			.get("credat:challenge")!
			.callback(createMockExtra("session-A"))) as CallToolResult;
		const challenge = parseResult(challengeResult) as unknown as ChallengeMessage;
		const presentation = await performHandshake(challenge, setup);

		// Try to auth from session-B
		await server.registeredTools
			.get("credat:authenticate")!
			.callback({ presentation }, createMockExtra("session-B"));

		expect(onAuthFailed).toHaveBeenCalledOnce();
		expect(onAuthFailed.mock.calls[0][0].code).toBe(McpAuthErrorCodes.SESSION_MISMATCH);
	});

	it("fires on verification failure (expired delegation)", async () => {
		const onAuthFailed = vi.fn<(event: AuthFailedEvent) => void>();
		const pastDate = new Date(Date.now() - 3_600_000).toISOString();
		const setup = await createTestSetup(["email:read"], pastDate);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			hooks: { onAuthFailed },
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		await authenticateSession(server, setup, createMockExtra());

		expect(onAuthFailed).toHaveBeenCalledOnce();
		expect(onAuthFailed.mock.calls[0][0].reason).toBe("Authentication failed.");
		expect(onAuthFailed.mock.calls[0][0].agentDid).toBe(setup.agent.did);
	});

	it("fires on configuration error (no key resolver)", async () => {
		const onAuthFailed = vi.fn<(event: AuthFailedEvent) => void>();
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			// No agentPublicKey, no resolveAgentKey
			hooks: { onAuthFailed },
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		await authenticateSession(server, setup, createMockExtra());

		expect(onAuthFailed).toHaveBeenCalledOnce();
		expect(onAuthFailed.mock.calls[0][0].code).toBe(McpAuthErrorCodes.CONFIGURATION_ERROR);
	});

	it("fires on resolveAgentKey error", async () => {
		const onAuthFailed = vi.fn<(event: AuthFailedEvent) => void>();
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			resolveAgentKey: async () => {
				throw new Error("DNS failed");
			},
			hooks: { onAuthFailed },
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		await authenticateSession(server, setup, createMockExtra());

		expect(onAuthFailed).toHaveBeenCalledOnce();
		expect(onAuthFailed.mock.calls[0][0].code).toBe(McpAuthErrorCodes.CONFIGURATION_ERROR);
		expect(onAuthFailed.mock.calls[0][0].reason).toContain("DNS failed");
	});

	it("fires on replay attempt", async () => {
		const onAuthFailed = vi.fn<(event: AuthFailedEvent) => void>();
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			hooks: { onAuthFailed },
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
		await server.registeredTools
			.get("credat:authenticate")!
			.callback({ presentation }, extra);
		expect(onAuthFailed).not.toHaveBeenCalled();

		// Replay fires onAuthFailed
		await server.registeredTools
			.get("credat:authenticate")!
			.callback({ presentation }, extra);
		expect(onAuthFailed).toHaveBeenCalledOnce();
		expect(onAuthFailed.mock.calls[0][0].code).toBe(McpAuthErrorCodes.NOT_AUTHENTICATED);
	});
});

// ══════════════════════════════════════════════════════════════
// onAccessDenied
// ══════════════════════════════════════════════════════════════

describe("hooks: onAccessDenied", () => {
	it("fires when unauthenticated agent calls protected tool", async () => {
		const onAccessDenied = vi.fn<(event: AccessDeniedEvent) => void>();
		const key = generateKeyPair("ES256");
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: key.publicKey,
			hooks: { onAccessDenied },
		});

		const handler = auth.protect({}, (_args: Record<string, unknown>) => ({
			content: [{ type: "text" as const, text: "unreachable" }],
		}));

		await handler({}, createMockExtra());

		expect(onAccessDenied).toHaveBeenCalledOnce();
		const event = onAccessDenied.mock.calls[0][0];
		expect(event.code).toBe(McpAuthErrorCodes.NOT_AUTHENTICATED);
		expect(event.agentDid).toBeUndefined();
	});

	it("fires with scope details when scopes (ALL) are insufficient", async () => {
		const onAccessDenied = vi.fn<(event: AccessDeniedEvent) => void>();
		const setup = await createTestSetup(["email:read"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			hooks: { onAccessDenied },
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);
		await authenticateSession(server, setup, createMockExtra());

		const handler = auth.protect(
			{ scopes: ["email:read", "email:send"] },
			(_args: Record<string, unknown>) => ({
				content: [{ type: "text" as const, text: "unreachable" }],
			}),
		);

		await handler({}, createMockExtra());

		expect(onAccessDenied).toHaveBeenCalledOnce();
		const event = onAccessDenied.mock.calls[0][0];
		expect(event.code).toBe(McpAuthErrorCodes.INSUFFICIENT_SCOPES);
		expect(event.agentDid).toBe(setup.agent.did);
		expect(event.requiredScopes).toEqual(["email:read", "email:send"]);
		expect(event.grantedScopes).toEqual(["email:read"]);
		expect(event.reason).toContain("email:send");
	});

	it("fires when anyScope has no matches", async () => {
		const onAccessDenied = vi.fn<(event: AccessDeniedEvent) => void>();
		const setup = await createTestSetup(["data:read"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			hooks: { onAccessDenied },
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);
		await authenticateSession(server, setup, createMockExtra());

		const handler = auth.protect(
			{ anyScope: ["admin", "superuser"] },
			(_args: Record<string, unknown>) => ({
				content: [{ type: "text" as const, text: "unreachable" }],
			}),
		);

		await handler({}, createMockExtra());

		expect(onAccessDenied).toHaveBeenCalledOnce();
		const event = onAccessDenied.mock.calls[0][0];
		expect(event.code).toBe(McpAuthErrorCodes.INSUFFICIENT_SCOPES);
		expect(event.requiredScopes).toEqual(["admin", "superuser"]);
	});

	it("fires with violations on constraint violation", async () => {
		const onAccessDenied = vi.fn<(event: AccessDeniedEvent) => void>();

		// Use protect directly with a pre-loaded session that has constraints
		const store = new SessionStore(3_600_000);
		store.set("__stdio__", {
			delegationResult: {
				valid: true as const,
				agent: "did:web:agents.example.com:test",
				owner: "did:web:owner.example.com",
				scopes: ["payment"],
				constraints: { maxTransactionValue: 100 },
				errors: [] as [],
			},
			authenticatedAt: Date.now(),
		});

		const protect = createProtect(store, { onAccessDenied });
		const handler = protect(
			{ constraintContext: { transactionValue: 500 } },
			(_args: Record<string, unknown>) => ({
				content: [{ type: "text" as const, text: "unreachable" }],
			}),
		);

		await handler({}, createMockExtra());

		expect(onAccessDenied).toHaveBeenCalledOnce();
		const event = onAccessDenied.mock.calls[0][0];
		expect(event.code).toBe(McpAuthErrorCodes.CONSTRAINT_VIOLATION);
		expect(event.agentDid).toBe("did:web:agents.example.com:test");
		expect(event.violations).toHaveLength(1);
		expect(event.violations![0].constraint).toBe("maxTransactionValue");
	});

	it("does not fire when access is granted", async () => {
		const onAccessDenied = vi.fn<(event: AccessDeniedEvent) => void>();
		const setup = await createTestSetup(["email:read"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			hooks: { onAccessDenied },
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);
		await authenticateSession(server, setup, createMockExtra());

		const handler = auth.protect(
			{ scopes: ["email:read"] },
			(_args: Record<string, unknown>) => ({
				content: [{ type: "text" as const, text: "ok" }],
			}),
		);

		const result = await handler({}, createMockExtra());
		expect(result.isError).toBeUndefined();
		expect(onAccessDenied).not.toHaveBeenCalled();
	});
});

// ══════════════════════════════════════════════════════════════
// onSessionRevoked
// ══════════════════════════════════════════════════════════════

describe("hooks: onSessionRevoked", () => {
	it("fires when a session is revoked", async () => {
		const onSessionRevoked = vi.fn<(event: SessionRevokedEvent) => void>();
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			hooks: { onSessionRevoked },
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);
		await authenticateSession(server, setup, createMockExtra());

		await auth.revokeSession();

		expect(onSessionRevoked).toHaveBeenCalledOnce();
		const event = onSessionRevoked.mock.calls[0][0];
		expect(event.sessionId).toBe("__stdio__");
		expect(event.timestamp).toBeLessThanOrEqual(Date.now());
	});

	it("fires with correct sessionId for HTTP sessions", async () => {
		const onSessionRevoked = vi.fn<(event: SessionRevokedEvent) => void>();
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			hooks: { onSessionRevoked },
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);
		await authenticateSession(server, setup, createMockExtra("http-session-42"));

		await auth.revokeSession("http-session-42");

		expect(onSessionRevoked.mock.calls[0][0].sessionId).toBe("http-session-42");
	});
});

// ══════════════════════════════════════════════════════════════
// Combined: all hooks in a single flow
// ══════════════════════════════════════════════════════════════

describe("hooks: full flow fires hooks in order", () => {
	it("challenge → auth success → protected call → revoke", async () => {
		const events: string[] = [];
		const hooks: CredatAuthHooks = {
			onChallenge: () => events.push("challenge"),
			onAuthenticated: () => events.push("authenticated"),
			onAuthFailed: () => events.push("authFailed"),
			onAccessDenied: () => events.push("accessDenied"),
			onSessionRevoked: () => events.push("sessionRevoked"),
		};

		const setup = await createTestSetup(["email:read"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			hooks,
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);
		const extra = createMockExtra();

		// 1. Challenge
		await authenticateSession(server, setup, extra);

		// 2. Successful protected call
		const handler = auth.protect(
			{ scopes: ["email:read"] },
			(_args: Record<string, unknown>) => ({
				content: [{ type: "text" as const, text: "ok" }],
			}),
		);
		await handler({}, extra);

		// 3. Revoke
		await auth.revokeSession();

		expect(events).toEqual(["challenge", "authenticated", "sessionRevoked"]);
	});

	it("challenge → auth fail → protected denied", async () => {
		const events: string[] = [];
		const hooks: CredatAuthHooks = {
			onChallenge: () => events.push("challenge"),
			onAuthenticated: () => events.push("authenticated"),
			onAuthFailed: () => events.push("authFailed"),
			onAccessDenied: () => events.push("accessDenied"),
			onSessionRevoked: () => events.push("sessionRevoked"),
		};

		const key = generateKeyPair("ES256");
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: key.publicKey,
			hooks,
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);
		const extra = createMockExtra();

		// 1. Challenge
		await server.registeredTools.get("credat:challenge")!.callback(extra);

		// 2. Auth with fake presentation (will fail — no agentPublicKey)
		const setup = await createTestSetup();
		const challengeResult = (await server.registeredTools
			.get("credat:challenge")!
			.callback(extra)) as CallToolResult;
		const challenge = parseResult(challengeResult) as unknown as ChallengeMessage;
		const presentation = await performHandshake(challenge, setup);
		await server.registeredTools
			.get("credat:authenticate")!
			.callback({ presentation }, extra);

		// 3. Protected call — should be denied (not authenticated)
		const handler = auth.protect({}, (_args: Record<string, unknown>) => ({
			content: [{ type: "text" as const, text: "unreachable" }],
		}));
		await handler({}, extra);

		expect(events).toEqual([
			"challenge", // first challenge
			"challenge", // second challenge
			"authFailed", // auth failed (no key)
			"accessDenied", // protected tool denied
		]);
	});
});

// ══════════════════════════════════════════════════════════════
// No hooks configured — does not throw
// ══════════════════════════════════════════════════════════════

describe("hooks: absent hooks do not throw", () => {
	it("works without any hooks configured", async () => {
		const setup = await createTestSetup(["email:read"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			// No hooks
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);
		const extra = createMockExtra();

		// Full flow should work without errors
		await authenticateSession(server, setup, extra);
		const handler = auth.protect(
			{ scopes: ["email:read"] },
			(_args: Record<string, unknown>) => ({
				content: [{ type: "text" as const, text: "ok" }],
			}),
		);
		const result = await handler({}, extra);
		expect(result.isError).toBeUndefined();

		await auth.revokeSession();
		expect(await auth.isAuthenticated()).toBe(false);
	});

	it("works with empty hooks object", async () => {
		const setup = await createTestSetup(["email:read"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			hooks: {},
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		await authenticateSession(server, setup, createMockExtra());
		expect(await auth.isAuthenticated()).toBe(true);
	});

	it("works with partial hooks (only some events)", async () => {
		const onAuthenticated = vi.fn<(event: AuthenticatedEvent) => void>();
		const setup = await createTestSetup(["email:read"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			hooks: { onAuthenticated }, // Only one hook
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		await authenticateSession(server, setup, createMockExtra());
		expect(onAuthenticated).toHaveBeenCalledOnce();

		// Other events fire without error even though hooks are not defined
		await auth.revokeSession();
	});
});

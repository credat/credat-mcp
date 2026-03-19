import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { createChallenge, generateKeyPair, presentCredentials } from "@credat/sdk";
import type { ChallengeMessage, PresentationMessage } from "@credat/sdk";
import { describe, expect, it } from "vitest";
import { CredatAuth } from "../src/auth.js";
import { McpAuthErrorCodes } from "../src/errors.js";
import type { ToolExtra } from "../src/types.js";
import {
	createMockExtra,
	createMockServer,
	createTestSetup,
	performHandshake,
} from "./helpers.js";

function parseResult(result: CallToolResult): Record<string, unknown> {
	return JSON.parse((result.content[0] as { text: string }).text);
}

describe("CredatAuth", () => {
	it("constructor validates required options", () => {
		const key = generateKeyPair("ES256");

		expect(() => new CredatAuth({ serverDid: "", ownerPublicKey: key.publicKey })).toThrow(
			"serverDid is required",
		);

		expect(
			() =>
				new CredatAuth({
					serverDid: "did:web:test.example.com",
					ownerPublicKey: new Uint8Array(0),
				}),
		).toThrow("ownerPublicKey is required");
	});

	it("install registers challenge and authenticate tools", () => {
		const key = generateKeyPair("ES256");
		const auth = new CredatAuth({
			serverDid: "did:web:test.example.com",
			ownerPublicKey: key.publicKey,
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		expect(server.registeredTools.has("credat:challenge")).toBe(true);
		expect(server.registeredTools.has("credat:authenticate")).toBe(true);
	});

	it("custom toolPrefix works", () => {
		const key = generateKeyPair("ES256");
		const auth = new CredatAuth({
			serverDid: "did:web:test.example.com",
			ownerPublicKey: key.publicKey,
			toolPrefix: "auth",
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		expect(server.registeredTools.has("auth:challenge")).toBe(true);
		expect(server.registeredTools.has("auth:authenticate")).toBe(true);
	});

	it("full auth flow: challenge → authenticate → protected call", async () => {
		const setup = await createTestSetup(["email:read", "email:send"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		const extra = createMockExtra();

		// Step 1: Request challenge
		const challengeTool = server.registeredTools.get("credat:challenge")!;
		const challengeResult = challengeTool.callback(extra) as CallToolResult;
		const challenge: ChallengeMessage = parseResult(challengeResult) as unknown as ChallengeMessage;
		expect(challenge.type).toBe("credat:challenge");
		expect(challenge.nonce).toBeDefined();

		// Step 2: Present credentials
		const presentation = await performHandshake(challenge, setup);

		// Step 3: Authenticate
		const authTool = server.registeredTools.get("credat:authenticate")!;
		const authResult = (await authTool.callback(
			{ presentation },
			extra,
		)) as CallToolResult;
		expect(authResult.isError).toBeUndefined();
		const authData = parseResult(authResult);
		expect(authData.authenticated).toBe(true);
		expect(authData.scopes).toEqual(["email:read", "email:send"]);

		// Step 4: Call protected tool
		const protectedHandler = auth.protect(
			{ scopes: ["email:read"] },
			(_args: Record<string, unknown>, protectedExtra: ToolExtra & { auth: { agentDid: string } }) => ({
				content: [
					{
						type: "text" as const,
						text: `Authenticated as ${protectedExtra.auth.agentDid}`,
					},
				],
			}),
		);

		const toolResult = (await protectedHandler({}, extra)) as CallToolResult;
		expect(toolResult.isError).toBeUndefined();
		expect((toolResult.content[0] as { text: string }).text).toContain(
			setup.agent.did,
		);
	});

	it("rejects replay (reused nonce)", async () => {
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		const extra = createMockExtra();

		// Get challenge
		const challengeTool = server.registeredTools.get("credat:challenge")!;
		const challengeResult = challengeTool.callback(extra) as CallToolResult;
		const challenge = parseResult(challengeResult) as unknown as ChallengeMessage;

		const presentation = await performHandshake(challenge, setup);

		// First authenticate — should succeed
		const authTool = server.registeredTools.get("credat:authenticate")!;
		const first = (await authTool.callback(
			{ presentation },
			extra,
		)) as CallToolResult;
		expect(first.isError).toBeUndefined();

		// Replay same nonce — should fail
		const second = (await authTool.callback(
			{ presentation },
			extra,
		)) as CallToolResult;
		expect(second.isError).toBe(true);
		const error = parseResult(second);
		expect(error.code).toBe(McpAuthErrorCodes.NOT_AUTHENTICATED);
	});

	it("rejects expired delegation", async () => {
		// Create delegation that expired 1 hour ago
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

		const challengeTool = server.registeredTools.get("credat:challenge")!;
		const challengeResult = challengeTool.callback(extra) as CallToolResult;
		const challenge = parseResult(challengeResult) as unknown as ChallengeMessage;

		const presentation = await performHandshake(challenge, setup);

		const authTool = server.registeredTools.get("credat:authenticate")!;
		const result = (await authTool.callback(
			{ presentation },
			extra,
		)) as CallToolResult;

		expect(result.isError).toBe(true);
		const error = parseResult(result);
		expect(error.error).toBe("Authentication failed.");
	});

	it("rejects wrong scopes on protected tool", async () => {
		const setup = await createTestSetup(["email:read"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		const extra = createMockExtra();

		// Authenticate
		const challengeResult = server.registeredTools
			.get("credat:challenge")!
			.callback(extra) as CallToolResult;
		const challenge = parseResult(challengeResult) as unknown as ChallengeMessage;
		const presentation = await performHandshake(challenge, setup);
		await server.registeredTools
			.get("credat:authenticate")!
			.callback({ presentation }, extra);

		// Call tool requiring scope agent doesn't have
		const protectedHandler = auth.protect(
			{ scopes: ["calendar:write"] },
			(_args: Record<string, unknown>) => ({
				content: [{ type: "text" as const, text: "should not reach" }],
			}),
		);

		const result = (await protectedHandler({}, extra)) as CallToolResult;
		expect(result.isError).toBe(true);
		const error = parseResult(result);
		expect(error.code).toBe(McpAuthErrorCodes.INSUFFICIENT_SCOPES);
	});

	it("rejects missing credentials (no auth)", async () => {
		const key = generateKeyPair("ES256");
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: key.publicKey,
		});

		const protectedHandler = auth.protect({}, (_args: Record<string, unknown>) => ({
			content: [{ type: "text" as const, text: "should not reach" }],
		}));

		const result = (await protectedHandler(
			{},
			createMockExtra(),
		)) as CallToolResult;
		expect(result.isError).toBe(true);
		const error = parseResult(result);
		expect(error.code).toBe(McpAuthErrorCodes.NOT_AUTHENTICATED);
	});

	it("rejects when no agentPublicKey and no resolveAgentKey", async () => {
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			// No agentPublicKey, no resolveAgentKey
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		const extra = createMockExtra();

		const challengeResult = server.registeredTools
			.get("credat:challenge")!
			.callback(extra) as CallToolResult;
		const challenge = parseResult(challengeResult) as unknown as ChallengeMessage;
		const presentation = await performHandshake(challenge, setup);

		const result = (await server.registeredTools
			.get("credat:authenticate")!
			.callback({ presentation }, extra)) as CallToolResult;

		expect(result.isError).toBe(true);
		const error = parseResult(result);
		expect(error.code).toBe(McpAuthErrorCodes.CONFIGURATION_ERROR);
	});

	it("resolveAgentKey callback is used for multi-agent", async () => {
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			resolveAgentKey: async (agentDid: string) => {
				if (agentDid === setup.agent.did) {
					return setup.agent.keyPair.publicKey;
				}
				throw new Error(`Unknown agent: ${agentDid}`);
			},
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		const extra = createMockExtra();

		const challengeResult = server.registeredTools
			.get("credat:challenge")!
			.callback(extra) as CallToolResult;
		const challenge = parseResult(challengeResult) as unknown as ChallengeMessage;
		const presentation = await performHandshake(challenge, setup);

		const result = (await server.registeredTools
			.get("credat:authenticate")!
			.callback({ presentation }, extra)) as CallToolResult;

		expect(result.isError).toBeUndefined();
		const data = parseResult(result);
		expect(data.authenticated).toBe(true);
	});

	it("session isolation between different sessionIds", async () => {
		const setup = await createTestSetup(["email:read"]);
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		// Authenticate on session-A
		const extraA = createMockExtra("session-A");
		const challengeA = server.registeredTools
			.get("credat:challenge")!
			.callback(extraA) as CallToolResult;
		const challenge = parseResult(challengeA) as unknown as ChallengeMessage;
		const presentation = await performHandshake(challenge, setup);
		await server.registeredTools
			.get("credat:authenticate")!
			.callback({ presentation }, extraA);

		// Session-A should be authenticated
		expect(auth.isAuthenticated("session-A")).toBe(true);

		// Session-B should NOT be authenticated
		expect(auth.isAuthenticated("session-B")).toBe(false);

		const protectedHandler = auth.protect({}, (_args: Record<string, unknown>) => ({
			content: [{ type: "text" as const, text: "ok" }],
		}));

		const resultB = (await protectedHandler(
			{},
			createMockExtra("session-B"),
		)) as CallToolResult;
		expect(resultB.isError).toBe(true);
	});

	it("session expiry forces re-authentication", async () => {
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
			sessionMaxAgeMs: 100, // 100ms
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		const extra = createMockExtra();

		// Authenticate
		const challengeResult = server.registeredTools
			.get("credat:challenge")!
			.callback(extra) as CallToolResult;
		const challenge = parseResult(challengeResult) as unknown as ChallengeMessage;
		const presentation = await performHandshake(challenge, setup);
		await server.registeredTools
			.get("credat:authenticate")!
			.callback({ presentation }, extra);

		// Should be authenticated now
		expect(auth.isAuthenticated()).toBe(true);

		// Wait for session to expire
		await new Promise((r) => setTimeout(r, 150));

		// Should no longer be authenticated
		expect(auth.isAuthenticated()).toBe(false);
	});

	it("revokeSession forces re-authentication", async () => {
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		const extra = createMockExtra();

		// Authenticate
		const challengeResult = server.registeredTools
			.get("credat:challenge")!
			.callback(extra) as CallToolResult;
		const challenge = parseResult(challengeResult) as unknown as ChallengeMessage;
		const presentation = await performHandshake(challenge, setup);
		await server.registeredTools
			.get("credat:authenticate")!
			.callback({ presentation }, extra);

		expect(auth.isAuthenticated()).toBe(true);

		// Revoke
		auth.revokeSession();

		expect(auth.isAuthenticated()).toBe(false);
	});

	it("rejects challenge from different session (session binding)", async () => {
		const setup = await createTestSetup();
		const auth = new CredatAuth({
			serverDid: "did:web:service.example.com",
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		});

		const server = createMockServer();
		auth.install(server as unknown as import("@modelcontextprotocol/sdk/server/mcp.js").McpServer);

		// Request challenge from session-A
		const extraA = createMockExtra("session-A");
		const challengeResult = server.registeredTools
			.get("credat:challenge")!
			.callback(extraA) as CallToolResult;
		const challenge = parseResult(challengeResult) as unknown as ChallengeMessage;
		const presentation = await performHandshake(challenge, setup);

		// Try to authenticate from session-B
		const extraB = createMockExtra("session-B");
		const result = (await server.registeredTools
			.get("credat:authenticate")!
			.callback({ presentation }, extraB)) as CallToolResult;

		expect(result.isError).toBe(true);
		const error = parseResult(result);
		expect(error.code).toBe(McpAuthErrorCodes.SESSION_MISMATCH);
	});
});

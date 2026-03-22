import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { ChallengeMessage } from "@credat/sdk";
import { describe, expect, it } from "vitest";
import { createChallengeHandler } from "../../src/tools/challenge.js";
import { createAuthenticateHandler } from "../../src/tools/authenticate.js";
import { ChallengeStore, SessionStore } from "../../src/session.js";
import { McpAuthErrorCodes } from "../../src/errors.js";
import type { CredatAuthOptions } from "../../src/types.js";
import { createMockExtra, createTestSetup, performHandshake } from "../helpers.js";

const SERVER_DID = "did:web:server.example.com";
const FIVE_MINUTES = 300_000;
const ONE_HOUR = 3_600_000;

function parseResult(result: CallToolResult): Record<string, unknown> {
	return JSON.parse((result.content[0] as { text: string }).text);
}

async function issueChallenge(
	challengeStore: ChallengeStore,
	sessionId?: string,
): Promise<ChallengeMessage> {
	const handler = createChallengeHandler(SERVER_DID, challengeStore);
	const extra = createMockExtra(sessionId);
	const result = await handler(extra);
	return parseResult(result) as unknown as ChallengeMessage;
}

describe("createAuthenticateHandler", () => {
	it("successful authentication stores session and returns authenticated: true", async () => {
		const setup = await createTestSetup(["email:read", "email:send"]);
		const challengeStore = new ChallengeStore(FIVE_MINUTES);
		const sessionStore = new SessionStore(ONE_HOUR);

		const config: CredatAuthOptions = {
			serverDid: SERVER_DID,
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		};

		const authenticateHandler = createAuthenticateHandler(config, challengeStore, sessionStore);
		const extra = createMockExtra();

		const challenge = await issueChallenge(challengeStore);
		const presentation = await performHandshake(challenge, setup);

		const result = await authenticateHandler({ presentation }, extra);

		expect(result.isError).toBeUndefined();
		const data = parseResult(result);
		expect(data.authenticated).toBe(true);
		expect(data.agent).toBe(setup.agent.did);
		expect(data.scopes).toEqual(["email:read", "email:send"]);

		// Verify session was stored
		const session = sessionStore.get("__stdio__");
		expect(session).toBeDefined();
		expect(session!.delegationResult.valid).toBe(true);
		expect(session!.delegationResult.agent).toBe(setup.agent.did);
	});

	it("rejects unknown nonce (consume returns undefined)", async () => {
		const setup = await createTestSetup();
		const challengeStore = new ChallengeStore(FIVE_MINUTES);
		const sessionStore = new SessionStore(ONE_HOUR);

		const config: CredatAuthOptions = {
			serverDid: SERVER_DID,
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		};

		const authenticateHandler = createAuthenticateHandler(config, challengeStore, sessionStore);
		const extra = createMockExtra();

		// Issue a challenge and perform handshake but don't store it in the store
		const challenge = await issueChallenge(challengeStore);
		const presentation = await performHandshake(challenge, setup);

		// Consume the challenge before authenticating so it's no longer available
		challengeStore.consume(challenge.nonce);

		const result = await authenticateHandler({ presentation }, extra);

		expect(result.isError).toBe(true);
		const error = parseResult(result);
		expect(error.code).toBe(McpAuthErrorCodes.NOT_AUTHENTICATED);
		expect(error.error).toContain("Unknown or expired challenge nonce");
	});

	it("rejects session mismatch (challenge from different session)", async () => {
		const setup = await createTestSetup();
		const challengeStore = new ChallengeStore(FIVE_MINUTES);
		const sessionStore = new SessionStore(ONE_HOUR);

		const config: CredatAuthOptions = {
			serverDid: SERVER_DID,
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		};

		const authenticateHandler = createAuthenticateHandler(config, challengeStore, sessionStore);

		// Issue challenge on session-A
		const challenge = await issueChallenge(challengeStore, "session-A");
		const presentation = await performHandshake(challenge, setup);

		// Attempt to authenticate on session-B
		const extraB = createMockExtra("session-B");
		const result = await authenticateHandler({ presentation }, extraB);

		expect(result.isError).toBe(true);
		const error = parseResult(result);
		expect(error.code).toBe(McpAuthErrorCodes.SESSION_MISMATCH);
		expect(error.error).toContain("different session");
	});

	it("rejects when no agentPublicKey and no resolveAgentKey configured", async () => {
		const setup = await createTestSetup();
		const challengeStore = new ChallengeStore(FIVE_MINUTES);
		const sessionStore = new SessionStore(ONE_HOUR);

		const config: CredatAuthOptions = {
			serverDid: SERVER_DID,
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			// No agentPublicKey, no resolveAgentKey
		};

		const authenticateHandler = createAuthenticateHandler(config, challengeStore, sessionStore);
		const extra = createMockExtra();

		const challenge = await issueChallenge(challengeStore);
		const presentation = await performHandshake(challenge, setup);

		const result = await authenticateHandler({ presentation }, extra);

		expect(result.isError).toBe(true);
		const error = parseResult(result);
		expect(error.code).toBe(McpAuthErrorCodes.CONFIGURATION_ERROR);
		expect(error.error).toContain("No agentPublicKey configured");
	});

	it("uses resolveAgentKey callback when no static key", async () => {
		const setup = await createTestSetup(["email:read"]);
		const challengeStore = new ChallengeStore(FIVE_MINUTES);
		const sessionStore = new SessionStore(ONE_HOUR);

		let resolvedDid: string | undefined;

		const config: CredatAuthOptions = {
			serverDid: SERVER_DID,
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			resolveAgentKey: async (agentDid: string) => {
				resolvedDid = agentDid;
				return setup.agent.keyPair.publicKey;
			},
		};

		const authenticateHandler = createAuthenticateHandler(config, challengeStore, sessionStore);
		const extra = createMockExtra();

		const challenge = await issueChallenge(challengeStore);
		const presentation = await performHandshake(challenge, setup);

		const result = await authenticateHandler({ presentation }, extra);

		expect(result.isError).toBeUndefined();
		const data = parseResult(result);
		expect(data.authenticated).toBe(true);
		expect(resolvedDid).toBe(setup.agent.did);
	});

	it("returns CONFIGURATION_ERROR when resolveAgentKey throws", async () => {
		const setup = await createTestSetup();
		const challengeStore = new ChallengeStore(FIVE_MINUTES);
		const sessionStore = new SessionStore(ONE_HOUR);

		const config: CredatAuthOptions = {
			serverDid: SERVER_DID,
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			resolveAgentKey: async (_agentDid: string) => {
				throw new Error("DID resolution failed: network timeout");
			},
		};

		const authenticateHandler = createAuthenticateHandler(config, challengeStore, sessionStore);
		const extra = createMockExtra();

		const challenge = await issueChallenge(challengeStore);
		const presentation = await performHandshake(challenge, setup);

		const result = await authenticateHandler({ presentation }, extra);

		expect(result.isError).toBe(true);
		const error = parseResult(result);
		expect(error.code).toBe(McpAuthErrorCodes.CONFIGURATION_ERROR);
		expect(error.error).toContain("Failed to resolve agent public key");
		expect(error.error).toContain("DID resolution failed: network timeout");
	});

	it("returns error when verifyPresentation fails (expired delegation)", async () => {
		// Create delegation that expired 1 hour ago
		const pastDate = new Date(Date.now() - 3_600_000).toISOString();
		const setup = await createTestSetup(["email:read"], pastDate);
		const challengeStore = new ChallengeStore(FIVE_MINUTES);
		const sessionStore = new SessionStore(ONE_HOUR);

		const config: CredatAuthOptions = {
			serverDid: SERVER_DID,
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		};

		const authenticateHandler = createAuthenticateHandler(config, challengeStore, sessionStore);
		const extra = createMockExtra();

		const challenge = await issueChallenge(challengeStore);
		const presentation = await performHandshake(challenge, setup);

		const result = await authenticateHandler({ presentation }, extra);

		expect(result.isError).toBe(true);
		const error = parseResult(result);
		expect(error.error).toBe("Authentication failed.");
		expect(error.details).toBeDefined();

		// Session should NOT have been stored
		const session = sessionStore.get("__stdio__");
		expect(session).toBeUndefined();
	});

	it("uses correct sessionId from HTTP transport", async () => {
		const setup = await createTestSetup(["email:read"]);
		const challengeStore = new ChallengeStore(FIVE_MINUTES);
		const sessionStore = new SessionStore(ONE_HOUR);

		const httpSessionId = "http-session-xyz-789";

		const config: CredatAuthOptions = {
			serverDid: SERVER_DID,
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		};

		const authenticateHandler = createAuthenticateHandler(config, challengeStore, sessionStore);

		// Issue challenge and authenticate with the same HTTP session
		const challenge = await issueChallenge(challengeStore, httpSessionId);
		const presentation = await performHandshake(challenge, setup);
		const extra = createMockExtra(httpSessionId);

		const result = await authenticateHandler({ presentation }, extra);

		expect(result.isError).toBeUndefined();
		const data = parseResult(result);
		expect(data.authenticated).toBe(true);

		// Session should be stored under the HTTP session ID
		const session = sessionStore.get(httpSessionId);
		expect(session).toBeDefined();

		// Should NOT be stored under __stdio__
		const stdioSession = sessionStore.get("__stdio__");
		expect(stdioSession).toBeUndefined();
	});

	it("uses __stdio__ sessionId when no sessionId provided", async () => {
		const setup = await createTestSetup(["email:read"]);
		const challengeStore = new ChallengeStore(FIVE_MINUTES);
		const sessionStore = new SessionStore(ONE_HOUR);

		const config: CredatAuthOptions = {
			serverDid: SERVER_DID,
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		};

		const authenticateHandler = createAuthenticateHandler(config, challengeStore, sessionStore);

		// Issue challenge and authenticate without sessionId (stdio)
		const challenge = await issueChallenge(challengeStore, undefined);
		const presentation = await performHandshake(challenge, setup);
		const extra = createMockExtra(undefined);

		const result = await authenticateHandler({ presentation }, extra);

		expect(result.isError).toBeUndefined();

		const session = sessionStore.get("__stdio__");
		expect(session).toBeDefined();
	});

	it("nonce is single-use (replay rejected after successful auth)", async () => {
		const setup = await createTestSetup(["email:read"]);
		const challengeStore = new ChallengeStore(FIVE_MINUTES);
		const sessionStore = new SessionStore(ONE_HOUR);

		const config: CredatAuthOptions = {
			serverDid: SERVER_DID,
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		};

		const authenticateHandler = createAuthenticateHandler(config, challengeStore, sessionStore);
		const extra = createMockExtra();

		const challenge = await issueChallenge(challengeStore);
		const presentation = await performHandshake(challenge, setup);

		// First call succeeds
		const first = await authenticateHandler({ presentation }, extra);
		expect(first.isError).toBeUndefined();

		// Replay with same nonce fails
		const second = await authenticateHandler({ presentation }, extra);
		expect(second.isError).toBe(true);
		const error = parseResult(second);
		expect(error.code).toBe(McpAuthErrorCodes.NOT_AUTHENTICATED);
	});

	it("resolveAgentKey receives non-Error throw as 'Unknown error'", async () => {
		const setup = await createTestSetup();
		const challengeStore = new ChallengeStore(FIVE_MINUTES);
		const sessionStore = new SessionStore(ONE_HOUR);

		const config: CredatAuthOptions = {
			serverDid: SERVER_DID,
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			resolveAgentKey: async (_agentDid: string) => {
				throw "string-error"; // Non-Error throw
			},
		};

		const authenticateHandler = createAuthenticateHandler(config, challengeStore, sessionStore);
		const extra = createMockExtra();

		const challenge = await issueChallenge(challengeStore);
		const presentation = await performHandshake(challenge, setup);

		const result = await authenticateHandler({ presentation }, extra);

		expect(result.isError).toBe(true);
		const error = parseResult(result);
		expect(error.code).toBe(McpAuthErrorCodes.CONFIGURATION_ERROR);
		expect(error.error).toContain("Unknown error");
	});

	it("stores authenticatedAt timestamp in session", async () => {
		const setup = await createTestSetup(["email:read"]);
		const challengeStore = new ChallengeStore(FIVE_MINUTES);
		const sessionStore = new SessionStore(ONE_HOUR);

		const config: CredatAuthOptions = {
			serverDid: SERVER_DID,
			ownerPublicKey: setup.ownerKeyPair.publicKey,
			agentPublicKey: setup.agent.keyPair.publicKey,
		};

		const authenticateHandler = createAuthenticateHandler(config, challengeStore, sessionStore);
		const extra = createMockExtra();

		const before = Date.now();
		const challenge = await issueChallenge(challengeStore);
		const presentation = await performHandshake(challenge, setup);
		const result = await authenticateHandler({ presentation }, extra);
		const after = Date.now();

		expect(result.isError).toBeUndefined();

		const session = sessionStore.get("__stdio__");
		expect(session).toBeDefined();
		expect(session!.authenticatedAt).toBeGreaterThanOrEqual(before);
		expect(session!.authenticatedAt).toBeLessThanOrEqual(after);
	});
});

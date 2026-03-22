import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { ChallengeMessage } from "@credat/sdk";
import { describe, expect, it } from "vitest";
import { createChallengeHandler } from "../../src/tools/challenge.js";
import { ChallengeStore } from "../../src/session.js";
import { createMockExtra } from "../helpers.js";

const SERVER_DID = "did:web:server.example.com";
const FIVE_MINUTES = 300_000;

function parseResult(result: CallToolResult): Record<string, unknown> {
	return JSON.parse((result.content[0] as { text: string }).text);
}

describe("createChallengeHandler", () => {
	it("returns a valid challenge with nonce, timestamp, from, and type fields", async () => {
		const store = new ChallengeStore(FIVE_MINUTES);
		const handler = createChallengeHandler(SERVER_DID, store);
		const extra = createMockExtra();

		const result = await handler(extra);
		const challenge = parseResult(result) as unknown as ChallengeMessage;

		expect(challenge.nonce).toBeDefined();
		expect(typeof challenge.nonce).toBe("string");
		expect(challenge.nonce.length).toBeGreaterThan(0);
		expect(challenge.timestamp).toBeDefined();
		expect(challenge.from).toBeDefined();
		expect(challenge.type).toBe("credat:challenge");
	});

	it("uses serverDid in the 'from' field", async () => {
		const store = new ChallengeStore(FIVE_MINUTES);
		const customDid = "did:web:custom-server.example.com";
		const handler = createChallengeHandler(customDid, store);
		const extra = createMockExtra();

		const result = await handler(extra);
		const challenge = parseResult(result) as unknown as ChallengeMessage;

		expect(challenge.from).toBe(customDid);
	});

	it("stores challenge in the provided challenge store", async () => {
		const store = new ChallengeStore(FIVE_MINUTES);
		const handler = createChallengeHandler(SERVER_DID, store);
		const extra = createMockExtra();

		expect(store.size).toBe(0);

		const result = await handler(extra);
		const challenge = parseResult(result) as unknown as ChallengeMessage;

		expect(store.size).toBe(1);

		const stored = store.consume(challenge.nonce);
		expect(stored).toBeDefined();
		expect(stored!.challenge.nonce).toBe(challenge.nonce);
		expect(stored!.challenge.from).toBe(SERVER_DID);
	});

	it("uses sessionId from extra when provided (HTTP transport)", async () => {
		const store = new ChallengeStore(FIVE_MINUTES);
		const handler = createChallengeHandler(SERVER_DID, store);
		const httpSessionId = "http-session-abc-123";
		const extra = createMockExtra(httpSessionId);

		const result = await handler(extra);
		const challenge = parseResult(result) as unknown as ChallengeMessage;

		const stored = store.consume(challenge.nonce);
		expect(stored).toBeDefined();
		expect(stored!.sessionId).toBe(httpSessionId);
	});

	it("falls back to '__stdio__' when no sessionId (stdio transport)", async () => {
		const store = new ChallengeStore(FIVE_MINUTES);
		const handler = createChallengeHandler(SERVER_DID, store);
		const extra = createMockExtra(undefined);

		const result = await handler(extra);
		const challenge = parseResult(result) as unknown as ChallengeMessage;

		const stored = store.consume(challenge.nonce);
		expect(stored).toBeDefined();
		expect(stored!.sessionId).toBe("__stdio__");
	});

	it("generates unique nonces across multiple calls", async () => {
		const store = new ChallengeStore(FIVE_MINUTES);
		const handler = createChallengeHandler(SERVER_DID, store);
		const extra = createMockExtra();

		const nonces = new Set<string>();
		for (let i = 0; i < 10; i++) {
			const result = await handler(extra);
			const challenge = parseResult(result) as unknown as ChallengeMessage;
			nonces.add(challenge.nonce);
		}

		expect(nonces.size).toBe(10);
	});

	it("returned result is not isError", async () => {
		const store = new ChallengeStore(FIVE_MINUTES);
		const handler = createChallengeHandler(SERVER_DID, store);
		const extra = createMockExtra();

		const result = await handler(extra);

		expect(result.isError).toBeUndefined();
	});

	it("returned content is a single text entry with valid JSON", async () => {
		const store = new ChallengeStore(FIVE_MINUTES);
		const handler = createChallengeHandler(SERVER_DID, store);
		const extra = createMockExtra();

		const result = await handler(extra);

		expect(result.content).toHaveLength(1);
		expect(result.content[0]).toHaveProperty("type", "text");
		expect(() => JSON.parse((result.content[0] as { text: string }).text)).not.toThrow();
	});

	it("stores each challenge under distinct session when called with different sessions", async () => {
		const store = new ChallengeStore(FIVE_MINUTES);
		const handler = createChallengeHandler(SERVER_DID, store);

		const extraA = createMockExtra("session-A");
		const extraB = createMockExtra("session-B");

		const resultA = await handler(extraA);
		const resultB = await handler(extraB);

		const challengeA = parseResult(resultA) as unknown as ChallengeMessage;
		const challengeB = parseResult(resultB) as unknown as ChallengeMessage;

		expect(store.size).toBe(2);

		const storedA = store.consume(challengeA.nonce);
		const storedB = store.consume(challengeB.nonce);

		expect(storedA!.sessionId).toBe("session-A");
		expect(storedB!.sessionId).toBe("session-B");
	});

	it("challenge timestamp is close to current time", async () => {
		const store = new ChallengeStore(FIVE_MINUTES);
		const handler = createChallengeHandler(SERVER_DID, store);
		const extra = createMockExtra();

		const before = Date.now();
		const result = await handler(extra);
		const after = Date.now();

		const challenge = parseResult(result) as unknown as ChallengeMessage;
		const timestamp = new Date(challenge.timestamp).getTime();

		expect(timestamp).toBeGreaterThanOrEqual(before - 1000);
		expect(timestamp).toBeLessThanOrEqual(after + 1000);
	});
});

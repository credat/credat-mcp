import { createChallenge } from "credat";
import { describe, expect, it } from "vitest";
import { ChallengeStore, SessionStore } from "../src/session.js";
import type { SessionAuth } from "../src/types.js";

describe("ChallengeStore", () => {
	it("stores and consumes a challenge", () => {
		const store = new ChallengeStore(300_000);
		const challenge = createChallenge({ from: "did:web:test.example.com" });

		store.set(challenge.nonce, challenge, "session-1");

		const result = store.consume(challenge.nonce);
		expect(result).toBeDefined();
		expect(result!.challenge.nonce).toBe(challenge.nonce);
		expect(result!.sessionId).toBe("session-1");
	});

	it("returns undefined for unknown nonce", () => {
		const store = new ChallengeStore(300_000);

		const result = store.consume("nonexistent-nonce");
		expect(result).toBeUndefined();
	});

	it("consumes only once (replay prevention)", () => {
		const store = new ChallengeStore(300_000);
		const challenge = createChallenge({ from: "did:web:test.example.com" });

		store.set(challenge.nonce, challenge, "session-1");

		const first = store.consume(challenge.nonce);
		expect(first).toBeDefined();

		const second = store.consume(challenge.nonce);
		expect(second).toBeUndefined();
	});

	it("expires entries after TTL", () => {
		const store = new ChallengeStore(100); // 100ms TTL
		const challenge = createChallenge({ from: "did:web:test.example.com" });

		store.set(challenge.nonce, challenge, "session-1");

		// Manually backdate the entry
		const entry = (store as unknown as { store: Map<string, { createdAt: number }> }).store.get(
			challenge.nonce,
		);
		entry!.createdAt = Date.now() - 200;

		const result = store.consume(challenge.nonce);
		expect(result).toBeUndefined();
	});

	it("cleanup removes expired entries", () => {
		const store = new ChallengeStore(100);

		for (let i = 0; i < 5; i++) {
			const c = createChallenge({ from: "did:web:test.example.com" });
			store.set(c.nonce, c, "session-1");
		}

		expect(store.size).toBe(5);

		// Backdate all entries
		const internalStore = (store as unknown as { store: Map<string, { createdAt: number }> })
			.store;
		for (const entry of internalStore.values()) {
			entry.createdAt = Date.now() - 200;
		}

		store.cleanup();
		expect(store.size).toBe(0);
	});

	it("evicts when maxSize is exceeded", () => {
		const store = new ChallengeStore(300_000, 3);

		for (let i = 0; i < 5; i++) {
			const c = createChallenge({ from: "did:web:test.example.com" });
			store.set(c.nonce, c, "session-1");
		}

		// After cleanup/eviction, should be at or below maxSize
		expect(store.size).toBeLessThanOrEqual(3);
	});
});

describe("SessionStore", () => {
	const mockAuth: SessionAuth = {
		delegationResult: {
			valid: true as const,
			agent: "did:web:agents.example.com:agent-1",
			owner: "did:web:owner.example.com",
			scopes: ["email:read"],
			errors: [] as [],
		},
		authenticatedAt: Date.now(),
	};

	it("stores and retrieves auth", () => {
		const store = new SessionStore(3_600_000);

		store.set("session-1", mockAuth);

		const result = store.get("session-1");
		expect(result).toBeDefined();
		expect(result!.delegationResult.agent).toBe(
			"did:web:agents.example.com:agent-1",
		);
	});

	it("returns undefined for unknown session", () => {
		const store = new SessionStore(3_600_000);

		const result = store.get("nonexistent");
		expect(result).toBeUndefined();
	});

	it("returns undefined for expired session", () => {
		const store = new SessionStore(100); // 100ms TTL

		store.set("session-1", {
			...mockAuth,
			authenticatedAt: Date.now() - 200,
		});

		const result = store.get("session-1");
		expect(result).toBeUndefined();
	});

	it("delete revokes a session", () => {
		const store = new SessionStore(3_600_000);

		store.set("session-1", mockAuth);
		expect(store.get("session-1")).toBeDefined();

		store.delete("session-1");
		expect(store.get("session-1")).toBeUndefined();
	});

	it("cleanup removes expired entries", () => {
		const store = new SessionStore(100);

		store.set("session-1", {
			...mockAuth,
			authenticatedAt: Date.now() - 200,
		});
		store.set("session-2", {
			...mockAuth,
			authenticatedAt: Date.now(), // fresh
		});

		store.cleanup();
		expect(store.get("session-1")).toBeUndefined();
		expect(store.get("session-2")).toBeDefined();
	});
});

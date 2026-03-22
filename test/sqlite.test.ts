import Database from "better-sqlite3";
import { createChallenge } from "@credat/sdk";
import { describe, expect, it, beforeEach } from "vitest";
import { SqliteChallengeStore, SqliteSessionStore } from "../src/sqlite.js";
import type { SessionAuth } from "../src/types.js";

// ── Helpers ──

function createDb(): Database.Database {
	return new Database(":memory:");
}

function createMockAuth(overrides?: Partial<SessionAuth>): SessionAuth {
	return {
		delegationResult: {
			valid: true as const,
			agent: "did:web:agents.example.com:agent-1",
			owner: "did:web:owner.example.com",
			scopes: ["email:read", "email:send"],
			errors: [] as [],
		},
		authenticatedAt: Date.now(),
		...overrides,
	};
}

// ── SqliteChallengeStore ──

describe("SqliteChallengeStore", () => {
	let db: Database.Database;

	beforeEach(() => {
		db = createDb();
	});

	it("creates table on construction", () => {
		new SqliteChallengeStore(300_000, { db });

		const tables = db
			.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?")
			.get("credat_challenges") as { name: string } | undefined;

		expect(tables).toBeDefined();
		expect(tables!.name).toBe("credat_challenges");
	});

	it("set + consume: stores and retrieves correctly", () => {
		const store = new SqliteChallengeStore(300_000, { db });
		const challenge = createChallenge({ from: "did:web:test.example.com" });

		store.set(challenge.nonce, challenge, "session-1");

		const result = store.consume(challenge.nonce);
		expect(result).toBeDefined();
		expect(result!.challenge.nonce).toBe(challenge.nonce);
		expect(result!.challenge.type).toBe("credat:challenge");
		expect(result!.challenge.from).toBe("did:web:test.example.com");
		expect(result!.sessionId).toBe("session-1");
		expect(result!.createdAt).toBeTypeOf("number");
	});

	it("consume returns undefined for unknown nonce", () => {
		const store = new SqliteChallengeStore(300_000, { db });

		const result = store.consume("nonexistent-nonce");
		expect(result).toBeUndefined();
	});

	it("consume is single-use (second consume returns undefined)", () => {
		const store = new SqliteChallengeStore(300_000, { db });
		const challenge = createChallenge({ from: "did:web:test.example.com" });

		store.set(challenge.nonce, challenge, "session-1");

		const first = store.consume(challenge.nonce);
		expect(first).toBeDefined();

		const second = store.consume(challenge.nonce);
		expect(second).toBeUndefined();
	});

	it("consume returns undefined for expired challenges", () => {
		const store = new SqliteChallengeStore(100, { db }); // 100ms TTL
		const challenge = createChallenge({ from: "did:web:test.example.com" });

		// Insert with a backdated created_at
		db.prepare(
			`INSERT INTO credat_challenges (nonce, challenge, session_id, created_at) VALUES (?, ?, ?, ?)`,
		).run(challenge.nonce, JSON.stringify(challenge), "session-1", Date.now() - 200);

		const result = store.consume(challenge.nonce);
		expect(result).toBeUndefined();

		// Row should also be deleted (single-use behavior even on expiry)
		const row = db
			.prepare("SELECT COUNT(*) as count FROM credat_challenges WHERE nonce = ?")
			.get(challenge.nonce) as { count: number };
		expect(row.count).toBe(0);
	});

	it("cleanup removes expired entries", () => {
		const store = new SqliteChallengeStore(100, { db }); // 100ms TTL

		// Insert 3 expired entries directly
		for (let i = 0; i < 3; i++) {
			const c = createChallenge({ from: "did:web:test.example.com" });
			db.prepare(
				`INSERT INTO credat_challenges (nonce, challenge, session_id, created_at) VALUES (?, ?, ?, ?)`,
			).run(c.nonce, JSON.stringify(c), "session-1", Date.now() - 200);
		}

		expect(store.size).toBe(3);

		store.cleanup();
		expect(store.size).toBe(0);
	});

	it("cleanup keeps fresh entries", () => {
		const store = new SqliteChallengeStore(300_000, { db });

		// Insert 2 fresh entries
		const fresh1 = createChallenge({ from: "did:web:test.example.com" });
		const fresh2 = createChallenge({ from: "did:web:test.example.com" });
		store.set(fresh1.nonce, fresh1, "session-1");
		store.set(fresh2.nonce, fresh2, "session-2");

		// Insert 1 expired entry directly
		const expired = createChallenge({ from: "did:web:test.example.com" });
		db.prepare(
			`INSERT INTO credat_challenges (nonce, challenge, session_id, created_at) VALUES (?, ?, ?, ?)`,
		).run(expired.nonce, JSON.stringify(expired), "session-3", Date.now() - 400_000);

		expect(store.size).toBe(3);

		store.cleanup();
		expect(store.size).toBe(2);

		// Fresh entries should still be consumable
		expect(store.consume(fresh1.nonce)).toBeDefined();
		expect(store.consume(fresh2.nonce)).toBeDefined();
	});

	it("size returns correct count", () => {
		const store = new SqliteChallengeStore(300_000, { db });

		expect(store.size).toBe(0);

		const c1 = createChallenge({ from: "did:web:test.example.com" });
		const c2 = createChallenge({ from: "did:web:test.example.com" });
		const c3 = createChallenge({ from: "did:web:test.example.com" });

		store.set(c1.nonce, c1, "session-1");
		expect(store.size).toBe(1);

		store.set(c2.nonce, c2, "session-1");
		store.set(c3.nonce, c3, "session-1");
		expect(store.size).toBe(3);

		store.consume(c1.nonce);
		expect(store.size).toBe(2);
	});

	it("custom table prefix works", () => {
		new SqliteChallengeStore(300_000, { db, tablePrefix: "myapp" });

		const tables = db
			.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?")
			.get("myapp_challenges") as { name: string } | undefined;

		expect(tables).toBeDefined();
		expect(tables!.name).toBe("myapp_challenges");

		// Default table should NOT exist
		const defaultTable = db
			.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?")
			.get("credat_challenges") as { name: string } | undefined;

		expect(defaultTable).toBeUndefined();
	});

	it("rejects invalid table prefix (SQL injection prevention)", () => {
		expect(() => new SqliteChallengeStore(300_000, { db, tablePrefix: "x; DROP TABLE users--" }))
			.toThrow("invalid tablePrefix");
		expect(() => new SqliteChallengeStore(300_000, { db, tablePrefix: "123abc" }))
			.toThrow("invalid tablePrefix");
		expect(() => new SqliteChallengeStore(300_000, { db, tablePrefix: "" }))
			.toThrow("invalid tablePrefix");
	});

	it("multiple challenges with different session IDs", () => {
		const store = new SqliteChallengeStore(300_000, { db });

		const c1 = createChallenge({ from: "did:web:test.example.com" });
		const c2 = createChallenge({ from: "did:web:test.example.com" });
		const c3 = createChallenge({ from: "did:web:test.example.com" });

		store.set(c1.nonce, c1, "session-A");
		store.set(c2.nonce, c2, "session-B");
		store.set(c3.nonce, c3, "session-C");

		expect(store.size).toBe(3);

		const result1 = store.consume(c1.nonce);
		expect(result1!.sessionId).toBe("session-A");

		const result2 = store.consume(c2.nonce);
		expect(result2!.sessionId).toBe("session-B");

		const result3 = store.consume(c3.nonce);
		expect(result3!.sessionId).toBe("session-C");
	});

	it("overwrite existing nonce via INSERT OR REPLACE", () => {
		const store = new SqliteChallengeStore(300_000, { db });
		const challenge = createChallenge({ from: "did:web:test.example.com" });

		store.set(challenge.nonce, challenge, "session-original");
		expect(store.size).toBe(1);

		// Overwrite with different session ID
		const updatedChallenge = createChallenge({ from: "did:web:updated.example.com" });
		// Use the same nonce but different challenge data
		store.set(challenge.nonce, updatedChallenge, "session-replaced");

		// Should still be 1 entry, not 2
		expect(store.size).toBe(1);

		const result = store.consume(challenge.nonce);
		expect(result).toBeDefined();
		expect(result!.sessionId).toBe("session-replaced");
		expect(result!.challenge.from).toBe("did:web:updated.example.com");
	});

	it("JSON serialization roundtrip preserves challenge data", () => {
		const store = new SqliteChallengeStore(300_000, { db });
		const challenge = createChallenge({ from: "did:web:test.example.com" });

		store.set(challenge.nonce, challenge, "session-1");

		const result = store.consume(challenge.nonce);
		expect(result).toBeDefined();
		expect(result!.challenge).toEqual(challenge);
		expect(result!.challenge.type).toBe(challenge.type);
		expect(result!.challenge.nonce).toBe(challenge.nonce);
		expect(result!.challenge.from).toBe(challenge.from);
		expect(result!.challenge.timestamp).toBe(challenge.timestamp);
	});

	it("handles concurrent stores without conflict", () => {
		const store = new SqliteChallengeStore(300_000, { db });

		const challenges = Array.from({ length: 50 }, () =>
			createChallenge({ from: "did:web:test.example.com" }),
		);

		for (const c of challenges) {
			store.set(c.nonce, c, `session-${c.nonce}`);
		}

		expect(store.size).toBe(50);

		// All should be consumable
		for (const c of challenges) {
			const result = store.consume(c.nonce);
			expect(result).toBeDefined();
			expect(result!.challenge.nonce).toBe(c.nonce);
		}

		expect(store.size).toBe(0);
	});
});

// ── SqliteSessionStore ──

describe("SqliteSessionStore", () => {
	let db: Database.Database;

	beforeEach(() => {
		db = createDb();
	});

	it("creates table on construction", () => {
		new SqliteSessionStore(3_600_000, { db });

		const tables = db
			.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?")
			.get("credat_sessions") as { name: string } | undefined;

		expect(tables).toBeDefined();
		expect(tables!.name).toBe("credat_sessions");
	});

	it("set + get: stores and retrieves correctly", () => {
		const store = new SqliteSessionStore(3_600_000, { db });
		const auth = createMockAuth();

		store.set("session-1", auth);

		const result = store.get("session-1");
		expect(result).toBeDefined();
		expect(result!.delegationResult.valid).toBe(true);
		expect(result!.delegationResult.agent).toBe("did:web:agents.example.com:agent-1");
		expect(result!.delegationResult.owner).toBe("did:web:owner.example.com");
		expect(result!.delegationResult.scopes).toEqual(["email:read", "email:send"]);
		expect(result!.delegationResult.errors).toEqual([]);
		expect(result!.authenticatedAt).toBe(auth.authenticatedAt);
	});

	it("get returns undefined for unknown session", () => {
		const store = new SqliteSessionStore(3_600_000, { db });

		const result = store.get("nonexistent");
		expect(result).toBeUndefined();
	});

	it("get returns undefined for expired session and deletes it", () => {
		const store = new SqliteSessionStore(100, { db }); // 100ms TTL

		const auth = createMockAuth({ authenticatedAt: Date.now() - 200 });
		store.set("session-1", auth);

		// Verify it was inserted
		const row = db
			.prepare("SELECT COUNT(*) as count FROM credat_sessions WHERE session_id = ?")
			.get("session-1") as { count: number };
		expect(row.count).toBe(1);

		// get should return undefined for expired
		const result = store.get("session-1");
		expect(result).toBeUndefined();

		// Row should be deleted after expired get
		const rowAfter = db
			.prepare("SELECT COUNT(*) as count FROM credat_sessions WHERE session_id = ?")
			.get("session-1") as { count: number };
		expect(rowAfter.count).toBe(0);
	});

	it("delete returns true for existing session", () => {
		const store = new SqliteSessionStore(3_600_000, { db });
		const auth = createMockAuth();

		store.set("session-1", auth);

		const deleted = store.delete("session-1");
		expect(deleted).toBe(true);

		// Should no longer be retrievable
		expect(store.get("session-1")).toBeUndefined();
	});

	it("delete returns false for non-existent session", () => {
		const store = new SqliteSessionStore(3_600_000, { db });

		const deleted = store.delete("nonexistent");
		expect(deleted).toBe(false);
	});

	it("cleanup removes expired entries", () => {
		const store = new SqliteSessionStore(100, { db }); // 100ms TTL

		// Expired session
		store.set("session-expired", createMockAuth({ authenticatedAt: Date.now() - 200 }));

		// Fresh session
		store.set("session-fresh", createMockAuth({ authenticatedAt: Date.now() }));

		expect(store.size).toBe(2);

		store.cleanup();
		expect(store.size).toBe(1);

		expect(store.get("session-expired")).toBeUndefined();
		expect(store.get("session-fresh")).toBeDefined();
	});

	it("cleanup keeps fresh entries", () => {
		const store = new SqliteSessionStore(300_000, { db });

		// Insert 3 fresh sessions
		store.set("session-1", createMockAuth());
		store.set("session-2", createMockAuth());
		store.set("session-3", createMockAuth());

		store.cleanup();
		expect(store.size).toBe(3);

		expect(store.get("session-1")).toBeDefined();
		expect(store.get("session-2")).toBeDefined();
		expect(store.get("session-3")).toBeDefined();
	});

	it("size returns correct count", () => {
		const store = new SqliteSessionStore(3_600_000, { db });

		expect(store.size).toBe(0);

		store.set("session-1", createMockAuth());
		expect(store.size).toBe(1);

		store.set("session-2", createMockAuth());
		store.set("session-3", createMockAuth());
		expect(store.size).toBe(3);

		store.delete("session-1");
		expect(store.size).toBe(2);
	});

	it("custom table prefix works", () => {
		new SqliteSessionStore(3_600_000, { db, tablePrefix: "myapp" });

		const tables = db
			.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?")
			.get("myapp_sessions") as { name: string } | undefined;

		expect(tables).toBeDefined();
		expect(tables!.name).toBe("myapp_sessions");

		// Default table should NOT exist
		const defaultTable = db
			.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?")
			.get("credat_sessions") as { name: string } | undefined;

		expect(defaultTable).toBeUndefined();
	});

	it("rejects invalid table prefix (SQL injection prevention)", () => {
		expect(() => new SqliteSessionStore(3_600_000, { db, tablePrefix: "x; DROP TABLE users--" }))
			.toThrow("invalid tablePrefix");
		expect(() => new SqliteSessionStore(3_600_000, { db, tablePrefix: "123abc" }))
			.toThrow("invalid tablePrefix");
		expect(() => new SqliteSessionStore(3_600_000, { db, tablePrefix: "" }))
			.toThrow("invalid tablePrefix");
	});

	it("overwrite existing session via INSERT OR REPLACE", () => {
		const store = new SqliteSessionStore(3_600_000, { db });

		const auth1 = createMockAuth({
			delegationResult: {
				valid: true as const,
				agent: "did:web:agents.example.com:agent-original",
				owner: "did:web:owner.example.com",
				scopes: ["email:read"],
				errors: [] as [],
			},
		});

		store.set("session-1", auth1);
		expect(store.size).toBe(1);

		const auth2 = createMockAuth({
			delegationResult: {
				valid: true as const,
				agent: "did:web:agents.example.com:agent-replaced",
				owner: "did:web:owner.example.com",
				scopes: ["email:read", "calendar:write"],
				errors: [] as [],
			},
		});

		store.set("session-1", auth2);

		// Should still be 1 entry, not 2
		expect(store.size).toBe(1);

		const result = store.get("session-1");
		expect(result).toBeDefined();
		expect(result!.delegationResult.agent).toBe("did:web:agents.example.com:agent-replaced");
		expect(result!.delegationResult.scopes).toEqual(["email:read", "calendar:write"]);
	});

	it("data persists across store instances using same db", () => {
		const store1 = new SqliteSessionStore(3_600_000, { db });
		const auth = createMockAuth();

		store1.set("session-persist", auth);
		expect(store1.get("session-persist")).toBeDefined();

		// Create a second store instance pointing to the same database
		const store2 = new SqliteSessionStore(3_600_000, { db });

		const result = store2.get("session-persist");
		expect(result).toBeDefined();
		expect(result!.delegationResult.agent).toBe(auth.delegationResult.agent);
		expect(result!.delegationResult.scopes).toEqual(auth.delegationResult.scopes);
		expect(result!.authenticatedAt).toBe(auth.authenticatedAt);
	});

	it("JSON serialization roundtrip preserves data", () => {
		const store = new SqliteSessionStore(3_600_000, { db });

		const now = Date.now();
		const auth: SessionAuth = {
			delegationResult: {
				valid: true as const,
				agent: "did:web:agents.example.com:agent-1",
				owner: "did:web:owner.example.com",
				scopes: ["email:read", "email:send", "calendar:write"],
				errors: [] as [],
			},
			authenticatedAt: now,
		};

		store.set("session-json", auth);

		const result = store.get("session-json");
		expect(result).toBeDefined();
		expect(result).toEqual(auth);
	});

	it("handles multiple sessions independently", () => {
		const store = new SqliteSessionStore(3_600_000, { db });

		const authA = createMockAuth({
			delegationResult: {
				valid: true as const,
				agent: "did:web:agents.example.com:agent-A",
				owner: "did:web:owner.example.com",
				scopes: ["email:read"],
				errors: [] as [],
			},
		});

		const authB = createMockAuth({
			delegationResult: {
				valid: true as const,
				agent: "did:web:agents.example.com:agent-B",
				owner: "did:web:owner.example.com",
				scopes: ["calendar:write"],
				errors: [] as [],
			},
		});

		store.set("session-A", authA);
		store.set("session-B", authB);

		expect(store.size).toBe(2);

		const resultA = store.get("session-A");
		expect(resultA!.delegationResult.agent).toBe("did:web:agents.example.com:agent-A");
		expect(resultA!.delegationResult.scopes).toEqual(["email:read"]);

		const resultB = store.get("session-B");
		expect(resultB!.delegationResult.agent).toBe("did:web:agents.example.com:agent-B");
		expect(resultB!.delegationResult.scopes).toEqual(["calendar:write"]);

		// Deleting A should not affect B
		store.delete("session-A");
		expect(store.get("session-A")).toBeUndefined();
		expect(store.get("session-B")).toBeDefined();
		expect(store.size).toBe(1);
	});

	it("delete after expiry returns false", () => {
		const store = new SqliteSessionStore(100, { db }); // 100ms TTL

		const auth = createMockAuth({ authenticatedAt: Date.now() - 200 });
		store.set("session-expired", auth);

		// get triggers the delete-on-expiry
		expect(store.get("session-expired")).toBeUndefined();

		// Now delete should return false since get already removed it
		expect(store.delete("session-expired")).toBe(false);
	});
});

// ── Cross-store isolation ──

describe("SqliteChallengeStore + SqliteSessionStore coexistence", () => {
	it("both stores can use the same database without conflicts", () => {
		const db = createDb();

		const challengeStore = new SqliteChallengeStore(300_000, { db });
		const sessionStore = new SqliteSessionStore(3_600_000, { db });

		// Verify both tables exist
		const tables = db
			.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
			.all() as { name: string }[];
		const tableNames = tables.map((t) => t.name);

		expect(tableNames).toContain("credat_challenges");
		expect(tableNames).toContain("credat_sessions");

		// Operations on one store should not affect the other
		const challenge = createChallenge({ from: "did:web:test.example.com" });
		challengeStore.set(challenge.nonce, challenge, "session-1");

		const auth = createMockAuth();
		sessionStore.set("session-1", auth);

		expect(challengeStore.size).toBe(1);
		expect(sessionStore.size).toBe(1);

		challengeStore.consume(challenge.nonce);
		expect(challengeStore.size).toBe(0);
		expect(sessionStore.size).toBe(1); // Unaffected
	});

	it("custom prefixes create separate table namespaces", () => {
		const db = createDb();

		new SqliteChallengeStore(300_000, { db, tablePrefix: "app1" });
		new SqliteChallengeStore(300_000, { db, tablePrefix: "app2" });
		new SqliteSessionStore(3_600_000, { db, tablePrefix: "app1" });
		new SqliteSessionStore(3_600_000, { db, tablePrefix: "app2" });

		const tables = db
			.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
			.all() as { name: string }[];
		const tableNames = tables.map((t) => t.name);

		expect(tableNames).toContain("app1_challenges");
		expect(tableNames).toContain("app2_challenges");
		expect(tableNames).toContain("app1_sessions");
		expect(tableNames).toContain("app2_sessions");
		expect(tableNames).toHaveLength(4);
	});
});

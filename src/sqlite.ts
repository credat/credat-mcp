import type { ChallengeMessage } from "@credat/sdk";
import type Database from "better-sqlite3";
import type { IChallengeStore, ISessionStore, SessionAuth, StoredChallenge } from "./types.js";

export interface SqliteStoreOptions {
	/** better-sqlite3 Database instance */
	db: Database.Database;
	/** Table name prefix (default: "credat"). Must be alphanumeric/underscore only. */
	tablePrefix?: string;
}

const VALID_PREFIX = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

function validatePrefix(prefix: string): string {
	if (!VALID_PREFIX.test(prefix)) {
		throw new Error(
			`SqliteStore: invalid tablePrefix "${prefix}" — must match /^[a-zA-Z_][a-zA-Z0-9_]*$/`,
		);
	}
	return prefix;
}

// ── SQLite Challenge Store ──

const CLEANUP_THRESHOLD = 100;

export class SqliteChallengeStore implements IChallengeStore {
	private readonly db: Database.Database;
	private readonly table: string;
	private readonly maxAgeMs: number;
	private insertsSinceCleanup = 0;

	constructor(maxAgeMs: number, options: SqliteStoreOptions) {
		this.db = options.db;
		const prefix = validatePrefix(options.tablePrefix ?? "credat");
		this.table = `${prefix}_challenges`;
		this.maxAgeMs = maxAgeMs;

		this.db.exec(`
			CREATE TABLE IF NOT EXISTS ${this.table} (
				nonce TEXT PRIMARY KEY,
				challenge TEXT NOT NULL,
				session_id TEXT NOT NULL,
				created_at INTEGER NOT NULL
			)
		`);
	}

	set(nonce: string, challenge: ChallengeMessage, sessionId: string): void {
		this.db
			.prepare(
				`INSERT OR REPLACE INTO ${this.table} (nonce, challenge, session_id, created_at)
				VALUES (?, ?, ?, ?)`,
			)
			.run(nonce, JSON.stringify(challenge), sessionId, Date.now());

		this.insertsSinceCleanup++;
		if (this.insertsSinceCleanup >= CLEANUP_THRESHOLD) {
			this.cleanup();
			this.insertsSinceCleanup = 0;
		}
	}

	consume(nonce: string): StoredChallenge | undefined {
		const now = Date.now();
		const row = this.db
			.prepare(`SELECT challenge, session_id, created_at FROM ${this.table} WHERE nonce = ?`)
			.get(nonce) as { challenge: string; session_id: string; created_at: number } | undefined;

		if (!row) return undefined;

		// Always delete (single-use)
		this.db.prepare(`DELETE FROM ${this.table} WHERE nonce = ?`).run(nonce);

		// Check expiry
		if (now - row.created_at > this.maxAgeMs) {
			return undefined;
		}

		return {
			challenge: JSON.parse(row.challenge) as ChallengeMessage,
			sessionId: row.session_id,
			createdAt: row.created_at,
		};
	}

	cleanup(): void {
		const cutoff = Date.now() - this.maxAgeMs;
		this.db.prepare(`DELETE FROM ${this.table} WHERE created_at < ?`).run(cutoff);
	}

	get size(): number {
		const row = this.db.prepare(`SELECT COUNT(*) as count FROM ${this.table}`).get() as {
			count: number;
		};
		return row.count;
	}
}

// ── SQLite Session Store ──

export class SqliteSessionStore implements ISessionStore {
	private readonly db: Database.Database;
	private readonly table: string;
	private readonly maxAgeMs: number;

	constructor(maxAgeMs: number, options: SqliteStoreOptions) {
		this.db = options.db;
		const prefix = validatePrefix(options.tablePrefix ?? "credat");
		this.table = `${prefix}_sessions`;
		this.maxAgeMs = maxAgeMs;

		this.db.exec(`
			CREATE TABLE IF NOT EXISTS ${this.table} (
				session_id TEXT PRIMARY KEY,
				auth TEXT NOT NULL,
				authenticated_at INTEGER NOT NULL
			)
		`);
	}

	set(sessionId: string, auth: SessionAuth): void {
		this.db
			.prepare(
				`INSERT OR REPLACE INTO ${this.table} (session_id, auth, authenticated_at)
				VALUES (?, ?, ?)`,
			)
			.run(sessionId, JSON.stringify(auth), auth.authenticatedAt);
	}

	get(sessionId: string): SessionAuth | undefined {
		const row = this.db
			.prepare(`SELECT auth, authenticated_at FROM ${this.table} WHERE session_id = ?`)
			.get(sessionId) as { auth: string; authenticated_at: number } | undefined;

		if (!row) return undefined;

		// Check expiry
		if (Date.now() - row.authenticated_at > this.maxAgeMs) {
			this.db.prepare(`DELETE FROM ${this.table} WHERE session_id = ?`).run(sessionId);
			return undefined;
		}

		return JSON.parse(row.auth) as SessionAuth;
	}

	delete(sessionId: string): boolean {
		const result = this.db.prepare(`DELETE FROM ${this.table} WHERE session_id = ?`).run(sessionId);
		return result.changes > 0;
	}

	cleanup(): void {
		const cutoff = Date.now() - this.maxAgeMs;
		this.db.prepare(`DELETE FROM ${this.table} WHERE authenticated_at < ?`).run(cutoff);
	}

	get size(): number {
		const row = this.db.prepare(`SELECT COUNT(*) as count FROM ${this.table}`).get() as {
			count: number;
		};
		return row.count;
	}
}

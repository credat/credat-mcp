import type { ChallengeMessage } from "credat";
import type { SessionAuth, StoredChallenge } from "./types.js";

const DEFAULT_MAX_SIZE = 1000;
const CLEANUP_THRESHOLD = 100;

// ── Challenge Store ──

export class ChallengeStore {
	private store = new Map<string, StoredChallenge>();
	private readonly maxAgeMs: number;
	private readonly maxSize: number;
	private insertsSinceCleanup = 0;

	constructor(maxAgeMs: number, maxSize = DEFAULT_MAX_SIZE) {
		this.maxAgeMs = maxAgeMs;
		this.maxSize = maxSize;
	}

	set(nonce: string, challenge: ChallengeMessage, sessionId: string): void {
		this.store.set(nonce, {
			challenge,
			sessionId,
			createdAt: Date.now(),
		});

		this.insertsSinceCleanup++;
		if (this.insertsSinceCleanup >= CLEANUP_THRESHOLD || this.store.size > this.maxSize) {
			this.cleanup();
			this.insertsSinceCleanup = 0;
		}
	}

	/** Consume a challenge (single-use). Returns and deletes. */
	consume(nonce: string): StoredChallenge | undefined {
		const entry = this.store.get(nonce);
		if (!entry) return undefined;

		this.store.delete(nonce);

		if (Date.now() - entry.createdAt > this.maxAgeMs) {
			return undefined;
		}

		return entry;
	}

	cleanup(): void {
		const now = Date.now();
		for (const [nonce, entry] of this.store) {
			if (now - entry.createdAt > this.maxAgeMs) {
				this.store.delete(nonce);
			}
		}

		// Evict oldest if still over max size
		if (this.store.size > this.maxSize) {
			const entries = [...this.store.entries()].sort((a, b) => a[1].createdAt - b[1].createdAt);
			const toRemove = entries.slice(0, this.store.size - this.maxSize);
			for (const [nonce] of toRemove) {
				this.store.delete(nonce);
			}
		}
	}

	get size(): number {
		return this.store.size;
	}
}

// ── Session Store ──

export class SessionStore {
	private store = new Map<string, SessionAuth>();
	private readonly maxAgeMs: number;
	private insertsSinceCleanup = 0;

	constructor(maxAgeMs: number) {
		this.maxAgeMs = maxAgeMs;
	}

	set(sessionId: string, auth: SessionAuth): void {
		this.store.set(sessionId, auth);

		this.insertsSinceCleanup++;
		if (this.insertsSinceCleanup >= CLEANUP_THRESHOLD) {
			this.cleanup();
			this.insertsSinceCleanup = 0;
		}
	}

	get(sessionId: string): SessionAuth | undefined {
		const entry = this.store.get(sessionId);
		if (!entry) return undefined;

		if (Date.now() - entry.authenticatedAt > this.maxAgeMs) {
			this.store.delete(sessionId);
			return undefined;
		}

		return entry;
	}

	delete(sessionId: string): boolean {
		return this.store.delete(sessionId);
	}

	cleanup(): void {
		const now = Date.now();
		for (const [sessionId, entry] of this.store) {
			if (now - entry.authenticatedAt > this.maxAgeMs) {
				this.store.delete(sessionId);
			}
		}
	}

	get size(): number {
		return this.store.size;
	}
}

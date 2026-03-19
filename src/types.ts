import type { DelegationConstraints, DelegationResult } from "credat";

// ── Constraint Types (defined locally — not yet exported by credat npm) ──

export interface ConstraintContext {
	transactionValue?: number;
	domain?: string;
	[key: string]: unknown;
}

export interface ConstraintViolation {
	constraint: string;
	message: string;
}

// ── Configuration ──

export interface CredatAuthOptions {
	/** DID of the server, used as the challenge issuer (e.g. "did:web:api.example.com") */
	serverDid: string;

	/** Public key of the owner who issued delegation credentials */
	ownerPublicKey: Uint8Array;

	/** Static agent public key (for single-agent scenarios) */
	agentPublicKey?: Uint8Array;

	/** Resolve an agent's public key from their DID (for multi-agent scenarios) */
	resolveAgentKey?: (agentDid: string) => Promise<Uint8Array>;

	/** Max age for challenges before they expire. Default: 300_000 (5 minutes) */
	challengeMaxAgeMs?: number;

	/** Max age for authenticated sessions. Default: 3_600_000 (1 hour) */
	sessionMaxAgeMs?: number;

	/** Tool name prefix. Default: "credat" → tools become "credat:challenge", "credat:authenticate" */
	toolPrefix?: string;
}

// ── Protection ──

export interface ProtectOptions {
	/** Required scopes — agent must have ALL of these */
	scopes?: string[];

	/** Required scopes — agent must have at least ONE of these */
	anyScope?: string[];

	/** Constraint context for runtime constraint validation */
	constraintContext?:
		| ConstraintContext
		| ((args: Record<string, unknown>) => ConstraintContext);
}

// ── Auth Context ──

export interface AuthContext {
	/** Authenticated agent's DID */
	agentDid: string;

	/** DID of the owner who delegated permissions */
	ownerDid: string;

	/** Granted scopes */
	scopes: string[];

	/** Delegation constraints (if any) */
	constraints?: DelegationConstraints;
}

// ── Session ──

export interface SessionAuth {
	delegationResult: DelegationResult & { valid: true };
	authenticatedAt: number;
}

export interface StoredChallenge {
	challenge: import("credat").ChallengeMessage;
	sessionId: string;
	createdAt: number;
}

// ── Error Payloads ──

export interface AuthErrorPayload {
	error: string;
	code: string;
	details?: string[];
}

// ── Tool Handler ──

/** Minimal subset of MCP's RequestHandlerExtra we depend on */
export interface ToolExtra {
	sessionId?: string;
	signal: AbortSignal;
	[key: string]: unknown;
}

export type { DelegationConstraints, DelegationResult };

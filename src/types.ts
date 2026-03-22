import type { ChallengeMessage, DelegationConstraints, DelegationResult } from "@credat/sdk";

// ── Utility Types ──

export type MaybePromise<T> = T | Promise<T>;

// ── Store Interfaces ──

export interface IChallengeStore {
	set(nonce: string, challenge: ChallengeMessage, sessionId: string): MaybePromise<void>;
	consume(nonce: string): MaybePromise<StoredChallenge | undefined>;
}

export interface ISessionStore {
	set(sessionId: string, auth: SessionAuth): MaybePromise<void>;
	get(sessionId: string): MaybePromise<SessionAuth | undefined>;
	delete(sessionId: string): MaybePromise<boolean>;
}

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

// ── Observability Hooks ──

export interface ChallengeEvent {
	sessionId: string;
	nonce: string;
	timestamp: number;
}

export interface AuthenticatedEvent {
	sessionId: string;
	agentDid: string;
	ownerDid: string;
	scopes: string[];
	timestamp: number;
}

export interface AuthFailedEvent {
	sessionId: string;
	code: string;
	reason: string;
	agentDid?: string;
	timestamp: number;
}

export interface AccessDeniedEvent {
	sessionId: string;
	code: string;
	reason: string;
	agentDid?: string;
	requiredScopes?: string[];
	grantedScopes?: string[];
	violations?: ConstraintViolation[];
	timestamp: number;
}

export interface SessionRevokedEvent {
	sessionId: string;
	timestamp: number;
}

export interface CredatAuthHooks {
	/** Fired when a new challenge is issued */
	onChallenge?: (event: ChallengeEvent) => void;
	/** Fired when authentication succeeds */
	onAuthenticated?: (event: AuthenticatedEvent) => void;
	/** Fired when the authenticate handler rejects (bad nonce, session mismatch, verification failure) */
	onAuthFailed?: (event: AuthFailedEvent) => void;
	/** Fired when a protected tool rejects (not authenticated, wrong scopes, constraint violation) */
	onAccessDenied?: (event: AccessDeniedEvent) => void;
	/** Fired when a session is explicitly revoked */
	onSessionRevoked?: (event: SessionRevokedEvent) => void;
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

	/** Tool name prefix. Default: "@credat/sdk" → tools become "credat:challenge", "credat:authenticate" */
	toolPrefix?: string;

	/** Custom challenge store (default: in-memory ChallengeStore) */
	challengeStore?: IChallengeStore;

	/** Custom session store (default: in-memory SessionStore) */
	sessionStore?: ISessionStore;

	/** Observability hooks for auth events */
	hooks?: CredatAuthHooks;
}

// ── Protection ──

export interface ProtectOptions {
	/** Required scopes — agent must have ALL of these */
	scopes?: string[];

	/** Required scopes — agent must have at least ONE of these */
	anyScope?: string[];

	/** Constraint context for runtime constraint validation */
	constraintContext?: ConstraintContext | ((args: Record<string, unknown>) => ConstraintContext);
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
	challenge: import("@credat/sdk").ChallengeMessage;
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

export type { ChallengeMessage, DelegationConstraints, DelegationResult };

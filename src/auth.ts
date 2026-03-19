import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { createProtect } from "./protect.js";
import { ChallengeStore, SessionStore } from "./session.js";
import { createAuthenticateHandler } from "./tools/authenticate.js";
import { createChallengeHandler } from "./tools/challenge.js";
import type {
	AuthContext,
	CredatAuthOptions,
	ProtectOptions,
	SessionAuth,
	ToolExtra,
} from "./types.js";

const DEFAULT_CHALLENGE_MAX_AGE_MS = 5 * 60 * 1000; // 5 minutes
const DEFAULT_SESSION_MAX_AGE_MS = 60 * 60 * 1000; // 1 hour
const DEFAULT_TOOL_PREFIX = "credat";

const STDIO_SESSION_KEY = "__stdio__";

type ProtectedHandler<TArgs> = (
	args: TArgs,
	extra: ToolExtra & { auth: AuthContext },
) => CallToolResult | Promise<CallToolResult>;

export class CredatAuth {
	private readonly config: Required<
		Pick<
			CredatAuthOptions,
			| "serverDid"
			| "ownerPublicKey"
			| "challengeMaxAgeMs"
			| "sessionMaxAgeMs"
			| "toolPrefix"
		>
	> &
		Pick<CredatAuthOptions, "agentPublicKey" | "resolveAgentKey">;

	private readonly challengeStore: ChallengeStore;
	private readonly sessionStore: SessionStore;
	private readonly protectFn: ReturnType<typeof createProtect>;

	constructor(options: CredatAuthOptions) {
		if (!options.serverDid) {
			throw new Error("CredatAuth: serverDid is required");
		}
		if (!options.ownerPublicKey || options.ownerPublicKey.length === 0) {
			throw new Error("CredatAuth: ownerPublicKey is required");
		}

		this.config = {
			serverDid: options.serverDid,
			ownerPublicKey: options.ownerPublicKey,
			agentPublicKey: options.agentPublicKey,
			resolveAgentKey: options.resolveAgentKey,
			challengeMaxAgeMs:
				options.challengeMaxAgeMs ?? DEFAULT_CHALLENGE_MAX_AGE_MS,
			sessionMaxAgeMs:
				options.sessionMaxAgeMs ?? DEFAULT_SESSION_MAX_AGE_MS,
			toolPrefix: options.toolPrefix ?? DEFAULT_TOOL_PREFIX,
		};

		this.challengeStore = new ChallengeStore(this.config.challengeMaxAgeMs);
		this.sessionStore = new SessionStore(this.config.sessionMaxAgeMs);
		this.protectFn = createProtect(this.sessionStore);
	}

	/** Register the credat:challenge and credat:authenticate tools on the server */
	install(server: McpServer): void {
		const prefix = this.config.toolPrefix;

		const challengeHandler = createChallengeHandler(
			this.config.serverDid,
			this.challengeStore,
		);

		const authenticateHandler = createAuthenticateHandler(
			this.config,
			this.challengeStore,
			this.sessionStore,
		);

		// Register challenge tool (no input — callback receives just extra)
		server.registerTool(
			`${prefix}:challenge`,
			{
				description:
					"Request an authentication challenge. Returns a nonce that must be signed with your delegation credential.",
			},
			(extra) => challengeHandler(extra as ToolExtra),
		);

		// Register authenticate tool
		server.registerTool(
			`${prefix}:authenticate`,
			{
				description:
					"Present your signed credentials to authenticate. Requires a presentation object containing delegation proof and signed nonce.",
				inputSchema: z.object({
					presentation: z.object({
						type: z.literal("credat:presentation"),
						delegation: z.string(),
						nonce: z.string(),
						proof: z.string(),
						from: z.string(),
					}),
				}),
			},
			(args, extra) =>
				authenticateHandler(
					args as {
						presentation: {
							type: "credat:presentation";
							delegation: string;
							nonce: string;
							proof: string;
							from: string;
						};
					},
					extra as ToolExtra,
				),
		);
	}

	/** Wrap a tool handler to require authentication + optional scope/constraint checks */
	protect<TArgs extends Record<string, unknown>>(
		options: ProtectOptions,
		handler: ProtectedHandler<TArgs>,
	) {
		return this.protectFn(options, handler);
	}

	/** Check if a session is currently authenticated */
	isAuthenticated(sessionId?: string): boolean {
		const key = sessionId ?? STDIO_SESSION_KEY;
		return this.sessionStore.get(key) !== undefined;
	}

	/** Get the auth result for a session */
	getSessionAuth(sessionId?: string): SessionAuth | undefined {
		const key = sessionId ?? STDIO_SESSION_KEY;
		return this.sessionStore.get(key);
	}

	/** Revoke a session, forcing re-authentication */
	revokeSession(sessionId?: string): void {
		const key = sessionId ?? STDIO_SESSION_KEY;
		this.sessionStore.delete(key);
	}
}

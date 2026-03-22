import type { PresentationMessage } from "@credat/sdk";
import { verifyPresentation } from "@credat/sdk";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { authError, McpAuthErrorCodes } from "../errors.js";
import type {
	CredatAuthHooks,
	CredatAuthOptions,
	IChallengeStore,
	ISessionStore,
	ToolExtra,
} from "../types.js";

const STDIO_SESSION_KEY = "__stdio__";

export function createAuthenticateHandler(
	config: CredatAuthOptions,
	challengeStore: IChallengeStore,
	sessionStore: ISessionStore,
	hooks?: CredatAuthHooks,
) {
	function emitFailed(sessionId: string, code: string, reason: string, agentDid?: string) {
		hooks?.onAuthFailed?.({ sessionId, code, reason, agentDid, timestamp: Date.now() });
	}

	return async (
		args: { presentation: PresentationMessage },
		extra: ToolExtra,
	): Promise<CallToolResult> => {
		const { presentation } = args;
		const sessionId = extra.sessionId ?? STDIO_SESSION_KEY;

		// 1. Consume challenge (single-use nonce)
		const stored = await challengeStore.consume(presentation.nonce);
		if (!stored) {
			const reason = "Unknown or expired challenge nonce. Request a new challenge.";
			emitFailed(sessionId, McpAuthErrorCodes.NOT_AUTHENTICATED, reason, presentation.from);
			return authError(reason, McpAuthErrorCodes.NOT_AUTHENTICATED);
		}

		// 2. Verify session binding
		if (stored.sessionId !== sessionId) {
			const reason = "Challenge was issued to a different session.";
			emitFailed(sessionId, McpAuthErrorCodes.SESSION_MISMATCH, reason, presentation.from);
			return authError(reason, McpAuthErrorCodes.SESSION_MISMATCH);
		}

		// 3. Resolve agent public key
		let agentPublicKey: Uint8Array;
		if (config.agentPublicKey) {
			agentPublicKey = config.agentPublicKey;
		} else if (config.resolveAgentKey) {
			try {
				agentPublicKey = await config.resolveAgentKey(presentation.from);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Unknown error";
				const reason = `Failed to resolve agent public key for ${presentation.from}: ${message}`;
				emitFailed(sessionId, McpAuthErrorCodes.CONFIGURATION_ERROR, reason, presentation.from);
				return authError(reason, McpAuthErrorCodes.CONFIGURATION_ERROR);
			}
		} else {
			const reason = "No agentPublicKey configured and no resolveAgentKey callback provided.";
			emitFailed(sessionId, McpAuthErrorCodes.CONFIGURATION_ERROR, reason);
			return authError(reason, McpAuthErrorCodes.CONFIGURATION_ERROR);
		}

		// 4. Verify presentation
		const result = await verifyPresentation(presentation, {
			challenge: stored.challenge,
			ownerPublicKey: config.ownerPublicKey,
			agentPublicKey,
			challengeMaxAgeMs: config.challengeMaxAgeMs,
		});

		if (!result.valid) {
			const details = result.errors.map((e) => `${e.code}: ${e.message}`);
			const code = result.errors[0]?.code ?? "HANDSHAKE_VERIFICATION_FAILED";
			emitFailed(sessionId, code, "Authentication failed.", presentation.from);
			return authError("Authentication failed.", code, details);
		}

		// 5. Store session auth
		await sessionStore.set(sessionId, {
			delegationResult: result,
			authenticatedAt: Date.now(),
		});

		hooks?.onAuthenticated?.({
			sessionId,
			agentDid: result.agent,
			ownerDid: result.owner,
			scopes: result.scopes,
			timestamp: Date.now(),
		});

		return {
			content: [
				{
					type: "text",
					text: JSON.stringify({
						authenticated: true,
						agent: result.agent,
						scopes: result.scopes,
					}),
				},
			],
		};
	};
}

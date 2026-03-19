import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { PresentationMessage } from "credat";
import { verifyPresentation } from "credat";
import { McpAuthErrorCodes, authError } from "../errors.js";
import type { ChallengeStore, SessionStore } from "../session.js";
import type { CredatAuthOptions, ToolExtra } from "../types.js";

const STDIO_SESSION_KEY = "__stdio__";

export function createAuthenticateHandler(
	config: CredatAuthOptions,
	challengeStore: ChallengeStore,
	sessionStore: SessionStore,
) {
	return async (
		args: { presentation: PresentationMessage },
		extra: ToolExtra,
	): Promise<CallToolResult> => {
		const { presentation } = args;
		const sessionId = extra.sessionId ?? STDIO_SESSION_KEY;

		// 1. Consume challenge (single-use nonce)
		const stored = challengeStore.consume(presentation.nonce);
		if (!stored) {
			return authError(
				"Unknown or expired challenge nonce. Request a new challenge.",
				McpAuthErrorCodes.NOT_AUTHENTICATED,
			);
		}

		// 2. Verify session binding
		if (stored.sessionId !== sessionId) {
			return authError(
				"Challenge was issued to a different session.",
				McpAuthErrorCodes.SESSION_MISMATCH,
			);
		}

		// 3. Resolve agent public key
		let agentPublicKey: Uint8Array;
		if (config.agentPublicKey) {
			agentPublicKey = config.agentPublicKey;
		} else if (config.resolveAgentKey) {
			try {
				agentPublicKey = await config.resolveAgentKey(
					presentation.from,
				);
			} catch (err) {
				const message =
					err instanceof Error ? err.message : "Unknown error";
				return authError(
					`Failed to resolve agent public key for ${presentation.from}: ${message}`,
					McpAuthErrorCodes.CONFIGURATION_ERROR,
				);
			}
		} else {
			return authError(
				"No agentPublicKey configured and no resolveAgentKey callback provided.",
				McpAuthErrorCodes.CONFIGURATION_ERROR,
			);
		}

		// 4. Verify presentation
		const result = await verifyPresentation(presentation, {
			challenge: stored.challenge,
			ownerPublicKey: config.ownerPublicKey,
			agentPublicKey,
			challengeMaxAgeMs: config.challengeMaxAgeMs,
		});

		if (!result.valid) {
			const details = result.errors.map(
				(e) => `${e.code}: ${e.message}`,
			);
			return authError(
				"Authentication failed.",
				result.errors[0]?.code ?? "HANDSHAKE_VERIFICATION_FAILED",
				details,
			);
		}

		// 5. Store session auth
		sessionStore.set(sessionId, {
			delegationResult: result,
			authenticatedAt: Date.now(),
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

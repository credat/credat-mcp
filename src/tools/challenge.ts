import { createChallenge } from "@credat/sdk";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { CredatAuthHooks, IChallengeStore, ToolExtra } from "../types.js";

const STDIO_SESSION_KEY = "__stdio__";

export function createChallengeHandler(
	serverDid: string,
	challengeStore: IChallengeStore,
	hooks?: CredatAuthHooks,
) {
	return async (extra: ToolExtra): Promise<CallToolResult> => {
		const challenge = createChallenge({ from: serverDid });
		const sessionId = extra.sessionId ?? STDIO_SESSION_KEY;

		await challengeStore.set(challenge.nonce, challenge, sessionId);

		hooks?.onChallenge?.({ sessionId, nonce: challenge.nonce, timestamp: Date.now() });

		return {
			content: [{ type: "text", text: JSON.stringify(challenge) }],
		};
	};
}

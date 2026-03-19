import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { createChallenge } from "credat";
import type { ChallengeStore } from "../session.js";
import type { ToolExtra } from "../types.js";

const STDIO_SESSION_KEY = "__stdio__";

export function createChallengeHandler(serverDid: string, challengeStore: ChallengeStore) {
	return (extra: ToolExtra): CallToolResult => {
		const challenge = createChallenge({ from: serverDid });
		const sessionId = extra.sessionId ?? STDIO_SESSION_KEY;

		challengeStore.set(challenge.nonce, challenge, sessionId);

		return {
			content: [{ type: "text", text: JSON.stringify(challenge) }],
		};
	};
}

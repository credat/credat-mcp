import {
	createAgent,
	createDidWeb,
	delegate,
	generateKeyPair,
	presentCredentials,
} from "credat";
import type {
	AgentIdentity,
	ChallengeMessage,
	DelegationCredential,
	KeyPair,
	PresentationMessage,
} from "credat";
import type { ToolExtra } from "../src/types.js";

export interface TestSetup {
	ownerKeyPair: KeyPair;
	ownerDid: string;
	agent: AgentIdentity;
	delegation: DelegationCredential;
}

export async function createTestSetup(
	scopes = ["email:read", "email:send"],
	validUntil?: string,
): Promise<TestSetup> {
	const ownerKeyPair = generateKeyPair("ES256");
	const ownerDid = createDidWeb("owner.example.com");

	const agent = await createAgent({
		domain: "agents.example.com",
		path: "test-agent",
		algorithm: "ES256",
	});

	const delegation = await delegate({
		agent: agent.did,
		owner: ownerDid,
		ownerKeyPair,
		scopes,
		validUntil,
	});

	return { ownerKeyPair, ownerDid, agent, delegation };
}

export async function performHandshake(
	challenge: ChallengeMessage,
	setup: TestSetup,
): Promise<PresentationMessage> {
	return presentCredentials({
		challenge,
		delegation: setup.delegation.token,
		agent: setup.agent,
	});
}

export function createMockExtra(sessionId?: string): ToolExtra {
	return {
		sessionId,
		signal: new AbortController().signal,
	};
}

export interface MockServer {
	registeredTools: Map<
		string,
		{
			config: Record<string, unknown>;
			callback: (...args: unknown[]) => unknown;
		}
	>;
	registerTool(
		name: string,
		config: Record<string, unknown>,
		callback: (...args: unknown[]) => unknown,
	): { remove: () => void };
}

export function createMockServer(): MockServer {
	const registeredTools = new Map<
		string,
		{
			config: Record<string, unknown>;
			callback: (...args: unknown[]) => unknown;
		}
	>();

	return {
		registeredTools,
		registerTool(name, config, callback) {
			registeredTools.set(name, { config, callback });
			return {
				remove: () => registeredTools.delete(name),
			};
		},
	};
}

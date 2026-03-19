/**
 * Example: MCP client authenticating with Credat
 *
 * This demonstrates the agent-side flow:
 * 1. Create agent identity + delegation from owner
 * 2. Connect to MCP server
 * 3. Call credat:challenge to get a nonce
 * 4. Sign the nonce with presentCredentials()
 * 5. Call credat:authenticate with the presentation
 * 6. Call protected tools
 *
 * Run: npx tsx examples/client.ts
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
	createAgent,
	createDidWeb,
	delegate,
	generateKeyPair,
	presentCredentials,
	uint8ArrayToBase64url,
} from "credat";
import type { ChallengeMessage } from "credat";

async function main() {
	// ── Step 1: Set up identities ──
	// In production, the owner generates these once and the agent stores its identity
	const ownerKeyPair = generateKeyPair("ES256");
	const ownerDid = createDidWeb("alice.example.com");

	const agent = await createAgent({
		domain: "agents.alice.example.com",
		path: "email-assistant",
		algorithm: "ES256",
	});

	// Owner delegates permissions to the agent
	const delegation = await delegate({
		agent: agent.did,
		owner: ownerDid,
		ownerKeyPair,
		scopes: ["email:read", "email:send"],
		constraints: {
			allowedDomains: ["example.com", "company.com"],
		},
		validUntil: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 24h
	});

	console.log("Agent DID:", agent.did);
	console.log("Owner public key:", uint8ArrayToBase64url(ownerKeyPair.publicKey));
	console.log("Delegation scopes:", ["email:read", "email:send"]);
	console.log();

	// ── Step 2: Connect to MCP server ──
	// In production, use the actual server transport
	const transport = new StdioClientTransport({
		command: "npx",
		args: ["tsx", "examples/server.ts"],
		env: {
			...process.env,
			OWNER_PUBLIC_KEY: uint8ArrayToBase64url(ownerKeyPair.publicKey),
		},
	});

	const client = new Client({ name: "email-agent", version: "1.0.0" });
	await client.connect(transport);
	console.log("Connected to MCP server");

	// ── Step 3: Request challenge ──
	const challengeResult = await client.callTool({
		name: "credat:challenge",
		arguments: {},
	});

	const challenge: ChallengeMessage = JSON.parse(
		(challengeResult.content as Array<{ type: string; text: string }>)[0].text,
	);
	console.log("Received challenge with nonce:", challenge.nonce.slice(0, 16) + "...");

	// ── Step 4: Sign the nonce ──
	const presentation = await presentCredentials({
		challenge,
		delegation: delegation.token,
		agent,
	});
	console.log("Signed nonce, presenting credentials...");

	// ── Step 5: Authenticate ──
	const authResult = await client.callTool({
		name: "credat:authenticate",
		arguments: { presentation },
	});

	const authData = JSON.parse(
		(authResult.content as Array<{ type: string; text: string }>)[0].text,
	);
	console.log("Authentication result:", authData);

	if (!authData.authenticated) {
		console.error("Authentication failed!");
		process.exit(1);
	}

	// ── Step 6: Call protected tools ──
	console.log("\nCalling protected tool: read-emails");
	const emailResult = await client.callTool({
		name: "read-emails",
		arguments: { query: "meeting", limit: 10 },
	});
	console.log(
		"Result:",
		(emailResult.content as Array<{ type: string; text: string }>)[0].text,
	);

	// ── Step 7: Call another protected tool ──
	console.log("\nCalling protected tool: send-email");
	const sendResult = await client.callTool({
		name: "send-email",
		arguments: {
			to: "bob@example.com",
			subject: "Meeting notes",
			body: "Here are the meeting notes from today.",
		},
	});
	console.log(
		"Result:",
		(sendResult.content as Array<{ type: string; text: string }>)[0].text,
	);

	// ── Step 8: Try calling without required scope ──
	console.log("\n--- Public tool (no auth required) ---");
	const healthResult = await client.callTool({
		name: "health",
		arguments: {},
	});
	console.log(
		"Health:",
		(healthResult.content as Array<{ type: string; text: string }>)[0].text,
	);

	await client.close();
	console.log("\nDone.");
}

main().catch(console.error);

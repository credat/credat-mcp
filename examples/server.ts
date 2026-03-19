/**
 * Example: MCP server with Credat authentication
 *
 * This server exposes three tools:
 * - health (public — no auth required)
 * - read-emails (protected — requires "email:read" scope)
 * - send-email (protected — requires "email:send" scope + domain constraint)
 *
 * Run: npx tsx examples/server.ts
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { base64urlToUint8Array } from "@credat/sdk";
import { z } from "zod";
import { CredatAuth } from "../src/index.js";

// The owner's public key (base64url-encoded)
// In production, load this from an environment variable
const OWNER_PUBLIC_KEY = process.env.OWNER_PUBLIC_KEY;
if (!OWNER_PUBLIC_KEY) {
	console.error("Error: OWNER_PUBLIC_KEY environment variable is required");
	process.exit(1);
}

// Create MCP server
const server = new McpServer({
	name: "email-service",
	version: "1.0.0",
});

// Create Credat auth
const auth = new CredatAuth({
	serverDid: "did:web:email-service.example.com",
	ownerPublicKey: base64urlToUint8Array(OWNER_PUBLIC_KEY),
	// For multi-agent: use resolveAgentKey instead of agentPublicKey
	// resolveAgentKey: async (agentDid) => {
	//   const didDoc = await resolveDID(agentDid);
	//   return jwkToPublicKey(didDoc.didDocument!.verificationMethod![0].publicKeyJwk!);
	// },
});

// Install auth tools (credat:challenge + credat:authenticate)
auth.install(server);

// Public tool — no auth required
server.registerTool(
	"health",
	{ description: "Health check — no authentication required" },
	() => ({
		content: [{ type: "text", text: JSON.stringify({ status: "ok" }) }],
	}),
);

// Protected tool — requires "email:read" scope
server.registerTool(
	"read-emails",
	{
		description: "Read emails (requires email:read scope)",
		inputSchema: z.object({
			query: z.string().describe("Search query"),
			limit: z.number().optional().describe("Max results"),
		}),
	},
	auth.protect(
		{ scopes: ["email:read"] },
		(args, extra) => {
			const { auth: authCtx } = extra;
			return {
				content: [
					{
						type: "text",
						text: JSON.stringify({
							agent: authCtx.agentDid,
							query: args.query,
							results: [
								{ subject: "Hello", from: "alice@example.com" },
								{ subject: "Meeting", from: "bob@example.com" },
							],
						}),
					},
				],
			};
		},
	),
);

// Protected tool — requires "email:send" scope + domain constraint
server.registerTool(
	"send-email",
	{
		description: "Send an email (requires email:send scope)",
		inputSchema: z.object({
			to: z.string().describe("Recipient email"),
			subject: z.string().describe("Email subject"),
			body: z.string().describe("Email body"),
		}),
	},
	auth.protect(
		{
			scopes: ["email:send"],
			constraintContext: (args) => ({
				domain: (args.to as string).split("@")[1],
			}),
		},
		(args, extra) => {
			return {
				content: [
					{
						type: "text",
						text: JSON.stringify({
							sent: true,
							to: args.to,
							subject: args.subject,
							by: extra.auth.agentDid,
						}),
					},
				],
			};
		},
	),
);

// Start the server
async function main() {
	const transport = new StdioServerTransport();
	await server.connect(transport);
	console.error("Email MCP server running on stdio (Credat auth enabled)");
}

main().catch(console.error);

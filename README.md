<p align="center">
  <a href="https://credat.io">
    <img alt="Credat" src="https://raw.githubusercontent.com/credat/credat/develop/logo.png" width="120" />
  </a>
</p>

<h1 align="center">@credat/mcp</h1>

<p align="center">
  <strong>Trust & authentication layer for MCP servers.</strong>
  <br />
  Verify agent identity, delegated permissions, and scopes — before any tool executes.
</p>

<div align="center">

[![npm](https://img.shields.io/npm/v/@credat/mcp?color=cb3837&logo=npm)](https://www.npmjs.com/package/@credat/mcp)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-yellow.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-22+-green?logo=node.js)](https://nodejs.org/)

</div>

<div align="center">
  <a href="https://github.com/credat/credat"><img src="https://img.shields.io/badge/Credat_SDK-GitHub-24292e?style=for-the-badge&logo=github" /></a>
  <a href="https://docs.credat.io"><img src="https://img.shields.io/badge/Docs-credat.io-0066cc?style=for-the-badge" /></a>
  <a href="https://www.npmjs.com/package/@credat/mcp"><img src="https://img.shields.io/badge/npm-@credat/mcp-cb3837?style=for-the-badge&logo=npm" /></a>
</div>

---

> Your MCP server trusts any agent that calls it. Should it?

Right now, MCP servers have no way to know _who_ is calling, _who authorized them_, or _what they're allowed to do_. Any agent can invoke any tool.

**`@credat/mcp`** fixes that in 3 lines:

```typescript
import { CredatAuth } from '@credat/mcp'

const auth = new CredatAuth({
  serverDid: 'did:web:api.example.com',
  ownerPublicKey: base64urlToUint8Array(process.env.OWNER_PUBLIC_KEY!),
})

auth.install(server) // registers auth tools
```

Then protect any tool:

```typescript
server.registerTool('read-emails', { ... },
  auth.protect({ scopes: ['email:read'] }, (args, extra) => {
    console.log(`Authorized agent: ${extra.auth.agentDid}`)
    // ... your tool logic
  })
)
```

**Zero dependencies** · **Peer deps only** · **Works with Stdio + HTTP** · **Full type safety**

## Install

```bash
npm install @credat/mcp credat @modelcontextprotocol/sdk
```

## How It Works

`@credat/mcp` implements a challenge-response handshake over MCP's tool-call interface:

```
Agent                              MCP Server
  │                                    │
  │  1. Call "credat:challenge"         │
  │ ─────────────────────────────────>  │  Generate nonce
  │  ← { nonce, timestamp }            │
  │                                    │
  │  [Sign nonce with delegation]      │
  │                                    │
  │  2. Call "credat:authenticate"      │
  │ ─────────────────────────────────>  │  Verify signature + delegation
  │  ← { authenticated, scopes }       │  Store session
  │                                    │
  │  3. Call "read-emails"              │
  │ ─────────────────────────────────>  │  Check session auth + scopes
  │  ← Tool result                     │  ✓ Execute tool
```

**Under the hood**, the Credat SDK verifies:
- The agent signed the nonce with its private key (proof of identity)
- The delegation credential was issued by the expected owner (trust chain)
- The credential hasn't expired or been revoked
- The agent has the required scopes for the tool

All using standard cryptography (ES256/EdDSA), DIDs, and SD-JWT Verifiable Credentials.

## Full Example

### Server

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { base64urlToUint8Array } from 'credat'
import { z } from 'zod'
import { CredatAuth } from '@credat/mcp'

const server = new McpServer({ name: 'email-service', version: '1.0.0' })

const auth = new CredatAuth({
  serverDid: 'did:web:email-service.example.com',
  ownerPublicKey: base64urlToUint8Array(process.env.OWNER_PUBLIC_KEY!),
  agentPublicKey: base64urlToUint8Array(process.env.AGENT_PUBLIC_KEY!),
})

auth.install(server)

// Public tool — no auth
server.registerTool('health', { description: 'Health check' }, () => ({
  content: [{ type: 'text', text: '{"status":"ok"}' }],
}))

// Protected tool — requires scope
server.registerTool('read-emails', {
  description: 'Read emails',
  inputSchema: z.object({ query: z.string() }),
}, auth.protect({ scopes: ['email:read'] }, (args, extra) => ({
  content: [{ type: 'text', text: JSON.stringify({
    agent: extra.auth.agentDid,
    results: [{ subject: 'Hello', from: 'alice@example.com' }],
  })}],
})))

const transport = new StdioServerTransport()
await server.connect(transport)
```

### Client (Agent)

```typescript
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { presentCredentials } from 'credat'
import type { ChallengeMessage } from 'credat'

// After connecting to the MCP server...

// Step 1: Request challenge
const challengeResult = await client.callTool({
  name: 'credat:challenge',
  arguments: {},
})
const challenge: ChallengeMessage = JSON.parse(challengeResult.content[0].text)

// Step 2: Sign nonce with your delegation
const presentation = await presentCredentials({
  challenge,
  delegation: myDelegation.token,
  agent: myAgentIdentity,
})

// Step 3: Authenticate
const authResult = await client.callTool({
  name: 'credat:authenticate',
  arguments: { presentation },
})

// Step 4: Call protected tools
const emails = await client.callTool({
  name: 'read-emails',
  arguments: { query: 'meeting notes' },
})
```

## API Reference

### `CredatAuth`

```typescript
const auth = new CredatAuth(options: CredatAuthOptions)
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `serverDid` | `string` | **required** | DID of the server (challenge issuer) |
| `ownerPublicKey` | `Uint8Array` | **required** | Public key of the delegation issuer |
| `agentPublicKey` | `Uint8Array` | — | Static agent key (single-agent) |
| `resolveAgentKey` | `(did: string) => Promise<Uint8Array>` | — | Dynamic key resolution (multi-agent) |
| `challengeMaxAgeMs` | `number` | `300000` | Challenge expiry (5 min) |
| `sessionMaxAgeMs` | `number` | `3600000` | Session expiry (1 hour) |
| `toolPrefix` | `string` | `"credat"` | Tool name prefix |

**Methods:**

- `auth.install(server)` — Register `credat:challenge` and `credat:authenticate` tools
- `auth.protect(options, handler)` — Wrap a tool handler with auth + scope checks
- `auth.isAuthenticated(sessionId?)` — Check if a session is authenticated
- `auth.getSessionAuth(sessionId?)` — Get the delegation result for a session
- `auth.revokeSession(sessionId?)` — Force re-authentication

### `protect(options, handler)`

```typescript
auth.protect({
  scopes: ['email:read'],           // ALL required
  anyScope: ['admin', 'email:*'],    // ANY required
  constraintContext: { domain: 'example.com' },  // Runtime constraints
  // or dynamic:
  constraintContext: (args) => ({ transactionValue: args.amount }),
}, (args, extra) => {
  extra.auth.agentDid     // Authenticated agent DID
  extra.auth.ownerDid     // Owner who issued the delegation
  extra.auth.scopes       // Granted scopes
  extra.auth.constraints  // Delegation constraints
  return { content: [{ type: 'text', text: 'result' }] }
})
```

## Error Codes

Auth errors are returned as tool-level errors (`isError: true`) so agents can parse and react:

```json
{
  "content": [{ "type": "text", "text": "{\"error\":\"...\",\"code\":\"...\"}" }],
  "isError": true
}
```

| Code | When |
|------|------|
| `NOT_AUTHENTICATED` | No session found, or challenge consumed/expired |
| `SESSION_EXPIRED` | Session exceeded `sessionMaxAgeMs` |
| `SESSION_MISMATCH` | Challenge was issued to a different session |
| `INSUFFICIENT_SCOPES` | Agent lacks required scopes |
| `CONSTRAINT_VIOLATION` | Runtime constraint check failed |
| `CONFIGURATION_ERROR` | No `agentPublicKey` or `resolveAgentKey` configured |

Credat SDK error codes (`HANDSHAKE_EXPIRED`, `DELEGATION_EXPIRED`, etc.) are passed through on verification failure.

## Security

- **Replay protection**: Nonces are single-use (consumed on verification)
- **Session binding**: Challenges are bound to the session that requested them
- **No tokens in tool args**: Auth state is per-session, not per-request
- **Lazy expiration**: No timers — TTL checked on access
- **Cryptographic verification**: ES256 (P-256) and EdDSA (Ed25519) via [@noble/curves](https://github.com/paulmillr/noble-curves)

## Built on Credat

This package is part of the [Credat](https://github.com/credat/credat) ecosystem — a trust layer for AI agents using DIDs and Verifiable Credentials.

See the [Credat SDK](https://github.com/credat/credat) for:
- Agent identity management
- Delegation credential issuance
- Scope and constraint systems
- Credential revocation

## License

Apache-2.0

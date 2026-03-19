import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { hasAllScopes, hasAnyScope, validateConstraints } from "credat";
import {
	McpAuthErrorCodes,
	authError,
	constraintError,
	scopeError,
} from "./errors.js";
import type { SessionStore } from "./session.js";
import type { AuthContext, ProtectOptions, ToolExtra } from "./types.js";

const STDIO_SESSION_KEY = "__stdio__";

type ProtectedHandler<TArgs> = (
	args: TArgs,
	extra: ToolExtra & { auth: AuthContext },
) => CallToolResult | Promise<CallToolResult>;

type ToolHandler<TArgs> = (
	args: TArgs,
	extra: ToolExtra,
) => CallToolResult | Promise<CallToolResult>;

export function createProtect(sessionStore: SessionStore) {
	return function protect<TArgs extends Record<string, unknown>>(
		options: ProtectOptions,
		handler: ProtectedHandler<TArgs>,
	): ToolHandler<TArgs> {
		return (args: TArgs, extra: ToolExtra) => {
			const sessionId = extra.sessionId ?? STDIO_SESSION_KEY;

			// 1. Check authentication
			const session = sessionStore.get(sessionId);
			if (!session) {
				return authError(
					"Not authenticated. Call the credat:challenge tool to begin authentication.",
					McpAuthErrorCodes.NOT_AUTHENTICATED,
				);
			}

			const { delegationResult } = session;

			// 2. Check required scopes (ALL)
			if (options.scopes && options.scopes.length > 0) {
				if (!hasAllScopes(delegationResult, options.scopes)) {
					return scopeError(options.scopes, delegationResult.scopes);
				}
			}

			// 3. Check required scopes (ANY)
			if (options.anyScope && options.anyScope.length > 0) {
				if (!hasAnyScope(delegationResult, options.anyScope)) {
					return scopeError(options.anyScope, delegationResult.scopes);
				}
			}

			// 4. Validate constraints
			if (options.constraintContext) {
				const context =
					typeof options.constraintContext === "function"
						? options.constraintContext(
								args as Record<string, unknown>,
							)
						: options.constraintContext;

				const violations = validateConstraints(
					delegationResult.constraints,
					context,
				);
				if (violations.length > 0) {
					return constraintError(violations);
				}
			}

			// 5. Build auth context and call handler
			const authContext: AuthContext = {
				agentDid: delegationResult.agent,
				ownerDid: delegationResult.owner,
				scopes: delegationResult.scopes,
				constraints: delegationResult.constraints,
			};

			const augmentedExtra = Object.assign({}, extra, {
				auth: authContext,
			});

			return handler(args, augmentedExtra);
		};
	};
}

import { hasAllScopes, hasAnyScope } from "@credat/sdk";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { validateConstraints } from "./constraints.js";
import { authError, constraintError, McpAuthErrorCodes, scopeError } from "./errors.js";
import type {
	AuthContext,
	CredatAuthHooks,
	ISessionStore,
	ProtectOptions,
	ToolExtra,
} from "./types.js";

const STDIO_SESSION_KEY = "__stdio__";

type ProtectedHandler<TArgs> = (
	args: TArgs,
	extra: ToolExtra & { auth: AuthContext },
) => CallToolResult | Promise<CallToolResult>;

type ToolHandler<TArgs> = (args: TArgs, extra: ToolExtra) => Promise<CallToolResult>;

export function createProtect(sessionStore: ISessionStore, hooks?: CredatAuthHooks) {
	return function protect<TArgs extends Record<string, unknown>>(
		options: ProtectOptions,
		handler: ProtectedHandler<TArgs>,
	): ToolHandler<TArgs> {
		return async (args: TArgs, extra: ToolExtra) => {
			const sessionId = extra.sessionId ?? STDIO_SESSION_KEY;

			// 1. Check authentication
			const session = await sessionStore.get(sessionId);
			if (!session) {
				const reason = "Not authenticated. Call the credat:challenge tool to begin authentication.";
				hooks?.onAccessDenied?.({
					sessionId,
					code: McpAuthErrorCodes.NOT_AUTHENTICATED,
					reason,
					timestamp: Date.now(),
				});
				return authError(reason, McpAuthErrorCodes.NOT_AUTHENTICATED);
			}

			const { delegationResult } = session;

			// 2. Check required scopes (ALL)
			if (options.scopes && options.scopes.length > 0) {
				if (!hasAllScopes(delegationResult, options.scopes)) {
					const missing = options.scopes.filter((s) => !delegationResult.scopes.includes(s));
					hooks?.onAccessDenied?.({
						sessionId,
						code: McpAuthErrorCodes.INSUFFICIENT_SCOPES,
						reason: `Missing scopes: ${missing.join(", ")}`,
						agentDid: delegationResult.agent,
						requiredScopes: options.scopes,
						grantedScopes: delegationResult.scopes,
						timestamp: Date.now(),
					});
					return scopeError(options.scopes, delegationResult.scopes);
				}
			}

			// 3. Check required scopes (ANY)
			if (options.anyScope && options.anyScope.length > 0) {
				if (!hasAnyScope(delegationResult, options.anyScope)) {
					hooks?.onAccessDenied?.({
						sessionId,
						code: McpAuthErrorCodes.INSUFFICIENT_SCOPES,
						reason: `None of required scopes matched: ${options.anyScope.join(", ")}`,
						agentDid: delegationResult.agent,
						requiredScopes: options.anyScope,
						grantedScopes: delegationResult.scopes,
						timestamp: Date.now(),
					});
					return scopeError(options.anyScope, delegationResult.scopes);
				}
			}

			// 4. Validate constraints
			if (options.constraintContext) {
				const context =
					typeof options.constraintContext === "function"
						? options.constraintContext(args as Record<string, unknown>)
						: options.constraintContext;

				const violations = validateConstraints(delegationResult.constraints, context);
				if (violations.length > 0) {
					hooks?.onAccessDenied?.({
						sessionId,
						code: McpAuthErrorCodes.CONSTRAINT_VIOLATION,
						reason: violations.map((v) => v.message).join("; "),
						agentDid: delegationResult.agent,
						violations,
						timestamp: Date.now(),
					});
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

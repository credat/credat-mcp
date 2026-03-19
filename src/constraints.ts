import type { DelegationConstraints } from "credat";
import type { ConstraintContext, ConstraintViolation } from "./types.js";

export function validateConstraints(
	constraints: DelegationConstraints | undefined,
	context: ConstraintContext,
): ConstraintViolation[] {
	if (!constraints) return [];

	const violations: ConstraintViolation[] = [];

	if (
		constraints.maxTransactionValue != null &&
		context.transactionValue != null
	) {
		if (context.transactionValue > constraints.maxTransactionValue) {
			violations.push({
				constraint: "maxTransactionValue",
				message: `${context.transactionValue} exceeds max ${constraints.maxTransactionValue}`,
			});
		}
	}

	if (constraints.allowedDomains != null && context.domain != null) {
		if (!constraints.allowedDomains.includes(context.domain)) {
			violations.push({
				constraint: "allowedDomains",
				message: `Domain "${context.domain}" is not in allowed list: ${constraints.allowedDomains.join(", ")}`,
			});
		}
	}

	if (
		constraints.rateLimit != null &&
		typeof context.rateLimit === "number"
	) {
		if (context.rateLimit > constraints.rateLimit) {
			violations.push({
				constraint: "rateLimit",
				message: `Rate ${context.rateLimit} exceeds limit ${constraints.rateLimit}`,
			});
		}
	}

	return violations;
}

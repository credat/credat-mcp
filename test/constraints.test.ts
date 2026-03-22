import type { DelegationConstraints } from "@credat/sdk";
import { describe, expect, it } from "vitest";
import { validateConstraints } from "../src/constraints.js";
import type { ConstraintContext } from "../src/types.js";

describe("validateConstraints", () => {
	// ── No constraints / empty inputs ──

	it("returns empty array when constraints is undefined", () => {
		const result = validateConstraints(undefined, { transactionValue: 100 });
		expect(result).toEqual([]);
	});

	it("returns empty array when constraints is an empty object", () => {
		const result = validateConstraints({}, { transactionValue: 100, domain: "example.com" });
		expect(result).toEqual([]);
	});

	it("returns empty array when context has no matching fields", () => {
		const constraints: DelegationConstraints = {
			maxTransactionValue: 1000,
			allowedDomains: ["example.com"],
			rateLimit: 50,
		};
		const result = validateConstraints(constraints, {});
		expect(result).toEqual([]);
	});

	// ── maxTransactionValue ──

	describe("maxTransactionValue", () => {
		it("passes when value is under the limit", () => {
			const result = validateConstraints({ maxTransactionValue: 1000 }, { transactionValue: 500 });
			expect(result).toEqual([]);
		});

		it("passes when value is exactly at the limit", () => {
			const result = validateConstraints({ maxTransactionValue: 1000 }, { transactionValue: 1000 });
			expect(result).toEqual([]);
		});

		it("fails when value exceeds the limit", () => {
			const result = validateConstraints({ maxTransactionValue: 1000 }, { transactionValue: 1500 });
			expect(result).toHaveLength(1);
			expect(result[0].constraint).toBe("maxTransactionValue");
			expect(result[0].message).toContain("1500");
			expect(result[0].message).toContain("1000");
		});

		it("passes when both constraint and value are zero", () => {
			const result = validateConstraints({ maxTransactionValue: 0 }, { transactionValue: 0 });
			expect(result).toEqual([]);
		});

		it("fails when value is positive and limit is zero", () => {
			const result = validateConstraints({ maxTransactionValue: 0 }, { transactionValue: 1 });
			expect(result).toHaveLength(1);
			expect(result[0].constraint).toBe("maxTransactionValue");
		});

		it("handles negative transaction values (under positive limit)", () => {
			const result = validateConstraints({ maxTransactionValue: 100 }, { transactionValue: -50 });
			expect(result).toEqual([]);
		});

		it("skips check when transactionValue is not in context", () => {
			const result = validateConstraints({ maxTransactionValue: 1000 }, { domain: "test.com" });
			expect(result).toEqual([]);
		});
	});

	// ── allowedDomains ──

	describe("allowedDomains", () => {
		it("passes when domain is in the allowed list", () => {
			const result = validateConstraints(
				{ allowedDomains: ["example.com", "test.com"] },
				{ domain: "example.com" },
			);
			expect(result).toEqual([]);
		});

		it("fails when domain is not in the allowed list", () => {
			const result = validateConstraints(
				{ allowedDomains: ["example.com", "test.com"] },
				{ domain: "evil.com" },
			);
			expect(result).toHaveLength(1);
			expect(result[0].constraint).toBe("allowedDomains");
			expect(result[0].message).toContain("evil.com");
			expect(result[0].message).toContain("example.com");
			expect(result[0].message).toContain("test.com");
		});

		it("fails when allowed list is empty", () => {
			const result = validateConstraints({ allowedDomains: [] }, { domain: "example.com" });
			expect(result).toHaveLength(1);
			expect(result[0].constraint).toBe("allowedDomains");
		});

		it("passes with a single-domain allowed list when domain matches", () => {
			const result = validateConstraints({ allowedDomains: ["only.com"] }, { domain: "only.com" });
			expect(result).toEqual([]);
		});

		it("is case-sensitive", () => {
			const result = validateConstraints(
				{ allowedDomains: ["Example.com"] },
				{ domain: "example.com" },
			);
			expect(result).toHaveLength(1);
			expect(result[0].constraint).toBe("allowedDomains");
		});

		it("skips check when domain is not in context", () => {
			const result = validateConstraints(
				{ allowedDomains: ["example.com"] },
				{ transactionValue: 100 },
			);
			expect(result).toEqual([]);
		});
	});

	// ── rateLimit ──

	describe("rateLimit", () => {
		it("passes when rate is under the limit", () => {
			const result = validateConstraints({ rateLimit: 100 }, { rateLimit: 50 });
			expect(result).toEqual([]);
		});

		it("passes when rate is exactly at the limit", () => {
			const result = validateConstraints({ rateLimit: 100 }, { rateLimit: 100 });
			expect(result).toEqual([]);
		});

		it("fails when rate exceeds the limit", () => {
			const result = validateConstraints({ rateLimit: 100 }, { rateLimit: 150 });
			expect(result).toHaveLength(1);
			expect(result[0].constraint).toBe("rateLimit");
			expect(result[0].message).toContain("150");
			expect(result[0].message).toContain("100");
		});

		it("passes when both constraint and rate are zero", () => {
			const result = validateConstraints({ rateLimit: 0 }, { rateLimit: 0 });
			expect(result).toEqual([]);
		});

		it("fails when rate is positive and limit is zero", () => {
			const result = validateConstraints({ rateLimit: 0 }, { rateLimit: 1 });
			expect(result).toHaveLength(1);
			expect(result[0].constraint).toBe("rateLimit");
		});

		it("skips check when rateLimit is not a number in context", () => {
			const result = validateConstraints({ rateLimit: 100 }, {
				rateLimit: "fast",
			} as unknown as ConstraintContext);
			expect(result).toEqual([]);
		});
	});

	// ── Multiple violations ──

	describe("multiple violations", () => {
		it("returns all violations when all three constraints are violated", () => {
			const constraints: DelegationConstraints = {
				maxTransactionValue: 1000,
				allowedDomains: ["safe.com"],
				rateLimit: 10,
			};
			const context: ConstraintContext = {
				transactionValue: 5000,
				domain: "evil.com",
				rateLimit: 100,
			};

			const result = validateConstraints(constraints, context);
			expect(result).toHaveLength(3);

			const constraintNames = result.map((v) => v.constraint);
			expect(constraintNames).toContain("maxTransactionValue");
			expect(constraintNames).toContain("allowedDomains");
			expect(constraintNames).toContain("rateLimit");
		});

		it("returns only the violated constraints, not passing ones", () => {
			const constraints: DelegationConstraints = {
				maxTransactionValue: 1000,
				allowedDomains: ["safe.com"],
				rateLimit: 100,
			};
			const context: ConstraintContext = {
				transactionValue: 500,
				domain: "evil.com",
				rateLimit: 50,
			};

			const result = validateConstraints(constraints, context);
			expect(result).toHaveLength(1);
			expect(result[0].constraint).toBe("allowedDomains");
		});
	});

	// ── Partial context ──

	describe("partial context", () => {
		it("only validates constraints that have matching context fields", () => {
			const constraints: DelegationConstraints = {
				maxTransactionValue: 1000,
				allowedDomains: ["safe.com"],
				rateLimit: 10,
			};

			const result = validateConstraints(constraints, { transactionValue: 5000 });
			expect(result).toHaveLength(1);
			expect(result[0].constraint).toBe("maxTransactionValue");
		});

		it("returns empty when context fields are present but constraints are not", () => {
			const result = validateConstraints(
				{},
				{ transactionValue: 5000, domain: "test.com", rateLimit: 999 },
			);
			expect(result).toEqual([]);
		});
	});

	// ── Extra unknown fields ──

	describe("extra unknown fields in context", () => {
		it("ignores extra fields that have no corresponding constraint", () => {
			const constraints: DelegationConstraints = {
				maxTransactionValue: 1000,
			};
			const context: ConstraintContext = {
				transactionValue: 500,
				domain: "example.com",
				customField: "some-value",
				anotherField: 42,
			};

			const result = validateConstraints(constraints, context);
			expect(result).toEqual([]);
		});

		it("still validates correctly with extra fields present alongside a violation", () => {
			const constraints: DelegationConstraints = {
				maxTransactionValue: 100,
			};
			const context: ConstraintContext = {
				transactionValue: 200,
				extraStuff: true,
			};

			const result = validateConstraints(constraints, context);
			expect(result).toHaveLength(1);
			expect(result[0].constraint).toBe("maxTransactionValue");
		});
	});
});

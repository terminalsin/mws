import { ruleAt, type Rule } from "@mws-dashboard/ui/validation";
import { BatchMeterUsage } from "@mws-dashboard/ui/model/marketplace-metering";

// The catalog has no AWS API (it is seeded through MWS's control API), so
// its forms take their rules from the metering model, which names the same
// values, and from what Marketplace accepts when a product is listed.

export const TITLE: Rule = { maxLength: 255 };

/** Pricing dimensions: the API identifiers usage is metered against. */
export const DIMENSIONS: Rule = {
  format: "list",
  item: { ...ruleAt(BatchMeterUsage, "UsageRecords.Dimension"), pattern: "^[A-Za-z0-9_.-]+$", hint: "Letters, digits, _ . and -" },
};

/** A buyer's AWS account id. */
export const ACCOUNT: Rule = {
  ...ruleAt(BatchMeterUsage, "UsageRecords.CustomerAWSAccountId"),
  pattern: "^\\d{12}$",
  hint: "12 digits",
  generate: "account",
};

export const QUANTITY: Rule = { ...ruleAt(BatchMeterUsage, "UsageRecords.Quantity") };

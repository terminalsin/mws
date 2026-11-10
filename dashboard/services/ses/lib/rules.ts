import type { Rule } from "@mws-dashboard/ui";
import { CreateConfigurationSet, CreateConfigurationSetEventDestination, CreateEmailTemplate } from "@mws-dashboard/ui/model/sesv2";
import { CreateReceiptRule, CreateReceiptRuleSet } from "@mws-dashboard/ui/model/ses";

// SES's naming rule for rule sets, rules, configuration sets, destinations
// and templates (the models leave it to the docs): ASCII letters, digits,
// underscores and dashes (periods too for receipt names), at most 64.
const NAME = { generate: "name" as const, maxLength: 64 };
export const CONFIG_SET_NAME: Rule = { ...CreateConfigurationSet.ConfigurationSetName, ...NAME, pattern: "^[A-Za-z0-9_-]+$", hint: "Letters, digits, _ and - only" };
export const DESTINATION_NAME: Rule = { ...CreateConfigurationSetEventDestination.EventDestinationName, ...NAME, pattern: "^[A-Za-z0-9_-]+$", hint: "Letters, digits, _ and - only" };
export const TEMPLATE_NAME: Rule = { ...CreateEmailTemplate.TemplateName, ...NAME, pattern: "^[A-Za-z0-9_-]+$", hint: "Letters, digits, _ and - only" };
export const RULE_SET_NAME: Rule = {
  ...CreateReceiptRuleSet.RuleSetName,
  ...NAME,
  pattern: "^[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?$",
  hint: "Letters, digits, _ . - ; starts and ends with a letter or digit",
};
export const RULE_NAME: Rule = { ...(CreateReceiptRule.Rule.fields?.Name ?? {}), ...RULE_SET_NAME };

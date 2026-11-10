"use server";

import {
  CreateAnomalyMonitorCommand,
  CreateAnomalySubscriptionCommand,
  CreateCostCategoryDefinitionCommand,
  DeleteAnomalyMonitorCommand,
  DeleteAnomalySubscriptionCommand,
  DeleteCostCategoryDefinitionCommand,
  type AnomalyMonitor,
  type CostCategoryRule,
} from "@aws-sdk/client-cost-explorer";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";

import { ce } from "../../lib/clients";

const list = (value: string) =>
  value
    .split(/[\s,]+/)
    .map((v) => v.trim())
    .filter(Boolean);

export async function createMonitor(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const name = required(form, "name", "Monitor name");
      const kind = text(form, "kind");
      let monitor: AnomalyMonitor;
      if (kind === "accounts") {
        const accounts = list(required(form, "accounts", "Accounts"));
        monitor = { MonitorName: name, MonitorType: "CUSTOM", MonitorSpecification: { Dimensions: { Key: "LINKED_ACCOUNT", Values: accounts } } };
      } else if (kind === "tag") {
        const key = required(form, "tagKey", "Tag key");
        const values = list(required(form, "tagValues", "Tag values"));
        monitor = { MonitorName: name, MonitorType: "CUSTOM", MonitorSpecification: { Tags: { Key: key, Values: values } } };
      } else {
        monitor = { MonitorName: name, MonitorType: "DIMENSIONAL", MonitorDimension: "SERVICE" };
      }
      await (await ce()).send(new CreateAnomalyMonitorCommand({ AnomalyMonitor: monitor }));
      return `Created monitor ${name}`;
    },
    // One AWS services monitor per account: the type is what to change.
    { revalidate: ["/ce/anomalies"], fields: { MonitorName: "name", LimitExceededException: "kind" } },
  );
}

export async function createSubscription(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const name = required(form, "name", "Subscription name");
      const monitor = required(form, "monitor", "Monitor");
      const frequency = required(form, "frequency", "Frequency") as "IMMEDIATE" | "DAILY" | "WEEKLY";
      const address = required(form, "address", frequency === "IMMEDIATE" ? "SNS topic" : "Email");
      const sns = address.startsWith("arn:");
      // AWS sends immediate alerts to SNS only and summaries to email only.
      if (sns !== (frequency === "IMMEDIATE")) {
        throw new FieldError("address", frequency === "IMMEDIATE" ? "Immediate alerts go to an SNS topic" : "Summaries go to an email address", "format");
      }
      const threshold = Number(required(form, "threshold", "Threshold"));
      await (await ce()).send(
        new CreateAnomalySubscriptionCommand({
          AnomalySubscription: {
            SubscriptionName: name,
            MonitorArnList: [monitor],
            Frequency: frequency,
            Subscribers: [{ Address: address, Type: sns ? "SNS" : "EMAIL" }],
            ThresholdExpression: { Dimensions: { Key: "ANOMALY_TOTAL_IMPACT_ABSOLUTE", Values: [String(threshold)], MatchOptions: ["GREATER_THAN_OR_EQUAL"] } },
          },
        }),
      );
      return `Created alert ${name}`;
    },
    {
      revalidate: ["/ce/anomalies"],
      fields: { SubscriptionName: "name", MonitorArnList: "monitor", Subscribers: "address", "Subscribers.Address": "address", UnknownMonitorException: "monitor" },
    },
  );
}

export async function createCostCategory(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const name = required(form, "name", "Name");
      const source = required(form, "rules", "Rules");
      let rules: CostCategoryRule[];
      try {
        rules = JSON.parse(source);
      } catch {
        throw new FieldError("rules", "Not valid JSON", "format");
      }
      if (!Array.isArray(rules) || rules.length === 0) throw new FieldError("rules", "A list of at least one rule", "format");
      const fallback = text(form, "default");
      try {
        await (await ce()).send(
          new CreateCostCategoryDefinitionCommand({ Name: name, RuleVersion: "CostCategoryExpression.v1", Rules: rules, ...(fallback ? { DefaultValue: fallback } : {}) }),
        );
      } catch (e) {
        // AWS reports a taken name as a ValidationException.
        if (e instanceof Error && /already exists/i.test(e.message)) throw new FieldError("name", "Already exists", "taken");
        throw e;
      }
      return `Created cost category ${name}`;
    },
    { revalidate: ["/ce/categories"], fields: { Name: "name", Rules: "rules", DefaultValue: "default" } },
  );
}

export async function deleteMonitor(arn: string) {
  return act(async () => {
    await (await ce()).send(new DeleteAnomalyMonitorCommand({ MonitorArn: arn }));
    return "Deleted monitor";
  }, "/ce/anomalies");
}

export async function deleteSubscription(arn: string) {
  return act(async () => {
    await (await ce()).send(new DeleteAnomalySubscriptionCommand({ SubscriptionArn: arn }));
    return "Deleted alert";
  }, "/ce/anomalies");
}

export async function deleteCostCategory(arn: string) {
  return act(async () => {
    await (await ce()).send(new DeleteCostCategoryDefinitionCommand({ CostCategoryArn: arn }));
    return "Deleted cost category";
  }, "/ce/categories");
}

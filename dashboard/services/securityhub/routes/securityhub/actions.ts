"use server";

import { BatchEnableStandardsCommand, BatchUpdateFindingsCommand, EnableSecurityHubCommand } from "@aws-sdk/client-securityhub";
import { act } from "@mws-dashboard/aws";

import { securityhub } from "../../lib/clients";

export async function enableHub() {
  return act(async () => {
    await (await securityhub()).send(new EnableSecurityHubCommand({ EnableDefaultStandards: true }));
    return "Security Hub enabled";
  }, "/securityhub");
}

export async function enableStandard(arn: string) {
  return act(async () => {
    await (await securityhub()).send(new BatchEnableStandardsCommand({ StandardsSubscriptionRequests: [{ StandardsArn: arn }] }));
    return "Standard enabled";
  }, "/securityhub");
}

export async function setWorkflow(id: string, product: string, status: "RESOLVED" | "SUPPRESSED" | "NOTIFIED") {
  return act(async () => {
    await (await securityhub()).send(new BatchUpdateFindingsCommand({ FindingIdentifiers: [{ Id: id, ProductArn: product }], Workflow: { Status: status } }));
    return status === "RESOLVED" ? "Resolved" : status === "SUPPRESSED" ? "Suppressed" : "Notified";
  }, "/securityhub");
}

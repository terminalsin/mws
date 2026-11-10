"use server";

import {
  ArchiveFindingsCommand,
  CreateDetectorCommand,
  CreateFilterCommand,
  CreateIPSetCommand,
  CreateSampleFindingsCommand,
  CreateThreatIntelSetCommand,
  DeleteFilterCommand,
  DeleteIPSetCommand,
  DeleteThreatIntelSetCommand,
  UpdateDetectorCommand,
  UpdateIPSetCommand,
  UpdateThreatIntelSetCommand,
  type ThreatIntelSetFormat,
} from "@aws-sdk/client-guardduty";
import { FieldError, act, required, text, type ActionResult } from "@mws-dashboard/aws";

import { MESSAGE_FIELDS, guardduty } from "../../lib/clients";

/** Send, turning GuardDuty's "the request is rejected because the <input>
 * ..." messages into errors on the field they concern. */
async function send(run: () => Promise<unknown>) {
  try {
    await run();
  } catch (e) {
    const message = e instanceof Error ? e.message : "";
    const hit = MESSAGE_FIELDS.find(([re]) => re.test(message));
    if (hit) throw new FieldError(hit[1], message.replace(/^The request is rejected because /, "").replace(/^\w/, (c) => c.toUpperCase()), hit[2]);
    throw e;
  }
}

export type ListKind = "trusted" | "threat";

export async function createList(detector: string, kind: ListKind, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const input = {
      DetectorId: detector,
      Name: required(form, "name", "Name"),
      Location: required(form, "location", "Location"),
      Format: (text(form, "format") || "TXT") as ThreatIntelSetFormat,
      Activate: text(form, "activate") === "on",
    };
    const client = await guardduty();
    await send(() => (kind === "trusted" ? client.send(new CreateIPSetCommand(input)) : client.send(new CreateThreatIntelSetCommand(input))));
    return `Added ${input.Name}`;
  }, { revalidate: ["/guardduty/lists"], fields: { Name: "name", Location: "location", Format: "format" } });
}

export async function setListActive(detector: string, kind: ListKind, id: string, activate: boolean) {
  return act(async () => {
    const client = await guardduty();
    if (kind === "trusted") await client.send(new UpdateIPSetCommand({ DetectorId: detector, IpSetId: id, Activate: activate }));
    else await client.send(new UpdateThreatIntelSetCommand({ DetectorId: detector, ThreatIntelSetId: id, Activate: activate }));
    return activate ? "Activated" : "Deactivated";
  }, "/guardduty/lists");
}

export async function deleteList(detector: string, kind: ListKind, id: string) {
  return act(async () => {
    const client = await guardduty();
    if (kind === "trusted") await client.send(new DeleteIPSetCommand({ DetectorId: detector, IpSetId: id }));
    else await client.send(new DeleteThreatIntelSetCommand({ DetectorId: detector, ThreatIntelSetId: id }));
    return "Deleted";
  }, "/guardduty/lists");
}

/** A suppression rule: a filter that archives matching findings as they
 * arrive. */
export async function createSuppressionRule(detector: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    const type = required(form, "type", "Finding type");
    const description = text(form, "description");
    const client = await guardduty();
    await send(() =>
      client.send(
        new CreateFilterCommand({
          DetectorId: detector,
          Name: name,
          Action: "ARCHIVE",
          ...(description ? { Description: description } : {}),
          FindingCriteria: { Criterion: { type: { Equals: [type] } } },
        }),
      ),
    );
    return `Created ${name}`;
  }, { revalidate: ["/guardduty/suppression", "/guardduty"], fields: { Name: "name", Description: "description" } });
}

export async function deleteSuppressionRule(detector: string, name: string) {
  return act(async () => {
    await (await guardduty()).send(new DeleteFilterCommand({ DetectorId: detector, FilterName: name }));
    return "Deleted";
  }, "/guardduty/suppression");
}

export async function enableGuardDuty() {
  return act(async () => {
    await (await guardduty()).send(new CreateDetectorCommand({ Enable: true, FindingPublishingFrequency: "FIFTEEN_MINUTES" }));
    return "GuardDuty enabled";
  }, "/guardduty", "/guardduty/lists", "/guardduty/suppression");
}

export async function sampleFindings(detector: string) {
  return act(async () => {
    await (await guardduty()).send(new CreateSampleFindingsCommand({ DetectorId: detector }));
    return "Sample findings generated";
  }, "/guardduty");
}

export async function archive(detector: string, id: string) {
  return act(async () => {
    await (await guardduty()).send(new ArchiveFindingsCommand({ DetectorId: detector, FindingIds: [id] }));
    return "Archived";
  }, "/guardduty");
}

export async function setDetector(detector: string, enable: boolean) {
  return act(async () => {
    await (await guardduty()).send(new UpdateDetectorCommand({ DetectorId: detector, Enable: enable }));
    return enable ? "Enabled" : "Suspended";
  }, "/guardduty");
}

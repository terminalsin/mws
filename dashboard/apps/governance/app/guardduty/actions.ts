"use server";

import { ArchiveFindingsCommand, CreateDetectorCommand, CreateSampleFindingsCommand, UpdateDetectorCommand } from "@aws-sdk/client-guardduty";
import { act } from "@mws-dashboard/aws";

import { guardduty } from "../../lib/clients";

export async function enableGuardDuty() {
  return act(async () => {
    await (await guardduty()).send(new CreateDetectorCommand({ Enable: true, FindingPublishingFrequency: "FIFTEEN_MINUTES" }));
    return "GuardDuty enabled";
  }, "/guardduty");
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

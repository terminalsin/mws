"use server";

import {
  ArchiveFindingsCommand,
  CreateMalwareProtectionPlanCommand,
  DeleteDetectorCommand,
  DeleteMalwareProtectionPlanCommand,
  SendObjectMalwareScanCommand,
  StartMalwareScanCommand,
  UnarchiveFindingsCommand,
  UpdateFilterCommand,
  UpdateFindingsFeedbackCommand,
  UpdateMalwareProtectionPlanCommand,
  type DetectorFeatureConfiguration,
  type Feedback,
  type FindingPublishingFrequency,
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
import { ensureRole, wantsAuto } from "@mws-dashboard/aws/auto";
import { redirect } from "next/navigation";

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
    const description = text(form, "description");
    const client = await guardduty();
    const rank = text(form, "rank");
    await send(() =>
      client.send(
        new CreateFilterCommand({
          DetectorId: detector,
          Name: name,
          Action: (text(form, "action") || "ARCHIVE") as "ARCHIVE" | "NOOP",
          ...(description ? { Description: description } : {}),
          ...(rank ? { Rank: Number(rank) } : {}),
          FindingCriteria: filterCriteria(form),
        }),
      ),
    );
    return `Created ${name}`;
  }, { revalidate: ["/guardduty/suppression", "/guardduty"], fields: { Name: "name", Description: "description" } });
}

/** A filter's criteria from its form: finding types (one or more, comma
 * separated), a minimum severity, a resource type. */
function filterCriteria(form: FormData) {
  const types = required(form, "type", "Finding type")
    .split(/[\s,]+/)
    .filter(Boolean);
  const min = text(form, "severity");
  const resource = text(form, "resource");
  return {
    Criterion: {
      type: { Equals: types },
      ...(min ? { severity: { GreaterThanOrEqual: Number(min) } } : {}),
      ...(resource ? { "resource.resourceType": { Equals: [resource] } } : {}),
    },
  };
}

export async function updateSuppressionRule(detector: string, name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const rank = text(form, "rank");
    await send(async () =>
      (await guardduty()).send(
        new UpdateFilterCommand({
          DetectorId: detector,
          FilterName: name,
          Action: (text(form, "action") || "ARCHIVE") as "ARCHIVE" | "NOOP",
          Description: text(form, "description"),
          ...(rank ? { Rank: Number(rank) } : {}),
          FindingCriteria: filterCriteria(form),
        }),
      ),
    );
    return `Saved ${name}`;
  }, { revalidate: ["/guardduty/suppression", "/guardduty"], fields: { Description: "description", Rank: "rank" } });
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

export async function unarchive(detector: string, id: string) {
  return act(async () => {
    await (await guardduty()).send(new UnarchiveFindingsCommand({ DetectorId: detector, FindingIds: [id] }));
    return "Unarchived";
  }, "/guardduty", "/guardduty/finding");
}

export async function feedback(detector: string, id: string, value: Feedback, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await guardduty()).send(new UpdateFindingsFeedbackCommand({ DetectorId: detector, FindingIds: [id], Feedback: value, Comments: text(form, "comments") || undefined }));
    return value === "USEFUL" ? "Marked useful" : "Marked not useful";
  }, "/guardduty", "/guardduty/finding");
}

const FEATURES = ["S3_DATA_EVENTS", "EKS_AUDIT_LOGS", "EBS_MALWARE_PROTECTION", "RDS_LOGIN_EVENTS", "LAMBDA_NETWORK_LOGS", "RUNTIME_MONITORING"] as const;

/** Protection plans and the publishing frequency, as the settings page edits them. */
export async function updateDetector(detector: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const on = new Set(form.getAll("feature").map(String));
    await (await guardduty()).send(
      new UpdateDetectorCommand({
        DetectorId: detector,
        FindingPublishingFrequency: (text(form, "frequency") || undefined) as FindingPublishingFrequency | undefined,
        Features: FEATURES.map((Name): DetectorFeatureConfiguration => ({ Name, Status: on.has(Name) ? "ENABLED" : "DISABLED" })),
      }),
    );
    return "Settings saved";
  }, "/guardduty/settings");
}

export async function deleteDetector(detector: string) {
  return act(async () => {
    await (await guardduty()).send(new DeleteDetectorCommand({ DetectorId: detector }));
    redirect("/guardduty");
  });
}

/** The role a malware protection plan works in S3 as. */
const roleName = (bucket: string) => {
  const name = `GuardDutyS3MalwareProtectionRole-${bucket}`;
  if (name.length <= 64) return name;
  // Too long: keep it unique to the bucket with a short hash.
  let h = 5381;
  for (const c of bucket) h = ((h * 33) ^ c.charCodeAt(0)) >>> 0;
  return `${name.slice(0, 57)}-${h.toString(36).slice(0, 6)}`;
};
const malwareRole = (bucket: string) => ({
  name: roleName(bucket),
  service: "malware-protection-plan.guardduty.amazonaws.com",
  statements: [
    { Effect: "Allow", Action: ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectTagging", "s3:PutObjectTagging", "s3:PutObjectVersionTagging", "s3:ListBucket", "s3:GetBucketNotification", "s3:PutBucketNotification"], Resource: [`arn:aws:s3:::${bucket}`, `arn:aws:s3:::${bucket}/*`] },
    { Effect: "Allow", Action: ["events:PutRule", "events:DeleteRule", "events:PutTargets", "events:RemoveTargets", "events:DescribeRule", "kms:Decrypt", "kms:GenerateDataKey"], Resource: "*" },
  ],
});

const PLAN_FIELDS = { Role: "role", "ProtectedResource.S3Bucket.BucketName": "bucket", ObjectPrefixes: "prefixes" };

export async function createMalwarePlan(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const bucket = required(form, "bucket", "Bucket");
      const Role = wantsAuto(form, "role") ? await ensureRole(malwareRole(bucket)) : text(form, "role");
      const prefixes = text(form, "prefixes")
        .split(/[\s,]+/)
        .filter(Boolean);
      const r = await (await guardduty()).send(
        new CreateMalwareProtectionPlanCommand({
          Role,
          ProtectedResource: { S3Bucket: { BucketName: bucket, ...(prefixes.length ? { ObjectPrefixes: prefixes } : {}) } },
          Actions: { Tagging: { Status: form.get("tagging") === "on" ? "ENABLED" : "DISABLED" } },
        }),
      );
      redirect(`/guardduty/malware/plan?id=${encodeURIComponent(r.MalwareProtectionPlanId!)}`);
    },
    { fields: PLAN_FIELDS },
  );
}

export async function updateMalwarePlan(id: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const prefixes = text(form, "prefixes")
        .split(/[\s,]+/)
        .filter(Boolean);
      await (await guardduty()).send(
        new UpdateMalwareProtectionPlanCommand({
          MalwareProtectionPlanId: id,
          Role: text(form, "role") || undefined,
          ProtectedResource: { S3Bucket: { ObjectPrefixes: prefixes } },
          Actions: { Tagging: { Status: form.get("tagging") === "on" ? "ENABLED" : "DISABLED" } },
        }),
      );
      return "Plan saved";
    },
    { revalidate: ["/guardduty/malware/plan", "/guardduty/malware"], fields: PLAN_FIELDS },
  );
}

export async function deleteMalwarePlan(id: string) {
  return act(async () => {
    await (await guardduty()).send(new DeleteMalwareProtectionPlanCommand({ MalwareProtectionPlanId: id }));
    redirect("/guardduty/malware");
  });
}

export async function scanObject(bucket: string, key: string) {
  return act(async () => {
    await (await guardduty()).send(new SendObjectMalwareScanCommand({ S3Object: { Bucket: bucket, Key: key } }));
    return `Scanned ${key}`;
  }, "/guardduty/malware/plan");
}

export async function startEbsScan(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const id = required(form, "instance", "Instance");
      const arn = id.startsWith("arn:") ? id : `arn:aws:ec2:${text(form, "region")}:${text(form, "account")}:instance/${id}`;
      const r = await (await guardduty()).send(new StartMalwareScanCommand({ ResourceArn: arn }));
      return `Scan ${r.ScanId} started`;
    },
    { revalidate: ["/guardduty/malware"], fields: { ResourceArn: "instance" } },
  );
}

export async function setDetector(detector: string, enable: boolean) {
  return act(async () => {
    await (await guardduty()).send(new UpdateDetectorCommand({ DetectorId: detector, Enable: enable }));
    return enable ? "Enabled" : "Suspended";
  }, "/guardduty");
}

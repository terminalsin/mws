"use server";

import {
  CreateConfigurationSetCommand,
  CreateConfigurationSetEventDestinationCommand,
  DeleteConfigurationSetCommand,
  DeleteConfigurationSetEventDestinationCommand,
  PutConfigurationSetDeliveryOptionsCommand,
  PutConfigurationSetReputationOptionsCommand,
  PutConfigurationSetSendingOptionsCommand,
  PutConfigurationSetSuppressionOptionsCommand,
  PutConfigurationSetTrackingOptionsCommand,
  UpdateConfigurationSetEventDestinationCommand,
  type EventDestinationDefinition,
  type EventType,
  type SuppressionListReason,
} from "@aws-sdk/client-sesv2";
import { act, FieldError, frameInfo, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { configSetHref, ses } from "../../lib/clients";

const reasons = (form: FormData) => form.getAll("suppress").filter((r): r is SuppressionListReason => r === "BOUNCE" || r === "COMPLAINT");
const FIELDS = {
  ConfigurationSetName: "name",
  AlreadyExistsException: "name",
  CustomRedirectDomain: "redirectDomain",
  TlsPolicy: "tls",
  MaxDeliverySeconds: "maxDelivery",
};

export async function createConfigSet(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    const redirectDomain = text(form, "redirectDomain");
    const suppress = reasons(form);
    await (await ses()).send(
      new CreateConfigurationSetCommand({
        ConfigurationSetName: name,
        SendingOptions: { SendingEnabled: form.get("sending") === "on" },
        ReputationOptions: { ReputationMetricsEnabled: form.get("reputation") === "on" },
        DeliveryOptions: { TlsPolicy: (text(form, "tls") || "OPTIONAL") as "REQUIRE" | "OPTIONAL" },
        TrackingOptions: redirectDomain ? { CustomRedirectDomain: redirectDomain } : undefined,
        SuppressionOptions: form.get("overrideSuppression") === "on" ? { SuppressedReasons: suppress } : undefined,
      }),
    );
    redirect(configSetHref(name));
  }, { fields: FIELDS });
}

export async function deleteConfigSet(name: string, back?: boolean) {
  return act(async () => {
    await (await ses()).send(new DeleteConfigurationSetCommand({ ConfigurationSetName: name }));
    if (back) redirect("/ses?tab=configsets");
    return `Deleted ${name}`;
  }, "/ses");
}

/** Every option on the General tab at once (each is its own SES call). */
export async function updateConfigSet(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ses();
    const redirectDomain = text(form, "redirectDomain");
    const maxDelivery = text(form, "maxDelivery");
    await client.send(new PutConfigurationSetSendingOptionsCommand({ ConfigurationSetName: name, SendingEnabled: form.get("sending") === "on" }));
    await client.send(new PutConfigurationSetReputationOptionsCommand({ ConfigurationSetName: name, ReputationMetricsEnabled: form.get("reputation") === "on" }));
    await client.send(
      new PutConfigurationSetDeliveryOptionsCommand({
        ConfigurationSetName: name,
        TlsPolicy: (text(form, "tls") || "OPTIONAL") as "REQUIRE" | "OPTIONAL",
        MaxDeliverySeconds: maxDelivery ? Number(maxDelivery) : undefined,
      }),
    );
    if (redirectDomain || text(form, "wasRedirect"))
      await client.send(new PutConfigurationSetTrackingOptionsCommand({ ConfigurationSetName: name, CustomRedirectDomain: redirectDomain || undefined }));
    await client.send(new PutConfigurationSetSuppressionOptionsCommand({ ConfigurationSetName: name, SuppressedReasons: form.get("overrideSuppression") === "on" ? reasons(form) : undefined }));
    return "Configuration set saved";
  }, { revalidate: ["/ses/configset"], fields: FIELDS });
}

const KINDS = ["sns", "eventbridge", "firehose", "cloudwatch"] as const;

async function destination(form: FormData): Promise<EventDestinationDefinition> {
  const types = form.getAll("event").filter((t): t is EventType => typeof t === "string" && !!t);
  if (!types.length) throw new FieldError("event", "Choose at least one event type", "required");
  const kind = text(form, "kind") as (typeof KINDS)[number];
  const base = { Enabled: form.get("enabled") === "on", MatchingEventTypes: types };
  switch (kind) {
    case "sns":
      return { ...base, SnsDestination: { TopicArn: required(form, "topic", "SNS topic") } };
    case "eventbridge": {
      const { account, region } = await frameInfo();
      return { ...base, EventBridgeDestination: { EventBusArn: text(form, "bus") || `arn:aws:events:${region}:${account}:event-bus/default` } };
    }
    case "firehose":
      return { ...base, KinesisFirehoseDestination: { DeliveryStreamArn: required(form, "stream", "Delivery stream"), IamRoleArn: required(form, "role", "IAM role") } };
    case "cloudwatch":
      return {
        ...base,
        CloudWatchDestination: {
          DimensionConfigurations: [
            {
              DimensionName: required(form, "dimension", "Dimension name"),
              DimensionValueSource: (text(form, "dimensionSource") || "MESSAGE_TAG") as "MESSAGE_TAG" | "EMAIL_HEADER" | "LINK_TAG",
              DefaultDimensionValue: required(form, "dimensionDefault", "Default value"),
            },
          ],
        },
      };
    default:
      throw new FieldError("kind", "Choose a destination", "required");
  }
}

const DEST_FIELDS = {
  EventDestinationName: "destName",
  AlreadyExistsException: "destName",
  TopicArn: "topic",
  EventBusArn: "bus",
  DeliveryStreamArn: "stream",
  IamRoleArn: "role",
  DimensionName: "dimension",
  DefaultDimensionValue: "dimensionDefault",
  MatchingEventTypes: "event",
};

export async function createEventDestination(configSet: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "destName", "Name");
    await (await ses()).send(new CreateConfigurationSetEventDestinationCommand({ ConfigurationSetName: configSet, EventDestinationName: name, EventDestination: await destination(form) }));
    return `Destination ${name} added`;
  }, { revalidate: ["/ses/configset"], fields: DEST_FIELDS });
}

export async function updateEventDestination(configSet: string, name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ses()).send(new UpdateConfigurationSetEventDestinationCommand({ ConfigurationSetName: configSet, EventDestinationName: name, EventDestination: await destination(form) }));
    return `Destination ${name} saved`;
  }, { revalidate: ["/ses/configset"], fields: DEST_FIELDS });
}

export async function deleteEventDestination(configSet: string, name: string) {
  return act(async () => {
    await (await ses()).send(new DeleteConfigurationSetEventDestinationCommand({ ConfigurationSetName: configSet, EventDestinationName: name }));
    return `Deleted ${name}`;
  }, "/ses/configset");
}

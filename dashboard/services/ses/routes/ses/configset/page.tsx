import { GetConfigurationSetCommand, GetConfigurationSetEventDestinationsCommand, type EventDestination } from "@aws-sdk/client-sesv2";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { Gauge, Lock, MousePointerClick, Pencil, Plus, Send, ShieldBan, Trash2, X } from "lucide-react";
import type { Metadata } from "next";

import { streams, topics } from "../../../lib/choices";
import { ICONS, ses } from "../../../lib/clients";
import { DestinationFields, type DestinationDefaults } from "../../../lib/forms";
import { DESTINATION_NAME } from "../../../lib/rules";
import { createEventDestination, deleteConfigSet, deleteEventDestination, updateConfigSet, updateEventDestination } from "../config-actions";

export const metadata: Metadata = { title: "Configuration set" };

type Props = { searchParams: Promise<{ name?: string }> };

function describe(d: EventDestination): { kind: DestinationDefaults["kind"]; icon: string; target: string; href?: string } {
  if (d.SnsDestination) return { kind: "sns", icon: ICONS.sns, target: d.SnsDestination.TopicArn ?? "", href: `/sns/topic?arn=${encodeURIComponent(d.SnsDestination.TopicArn ?? "")}` };
  if (d.EventBridgeDestination) return { kind: "eventbridge", icon: ICONS.events, target: d.EventBridgeDestination.EventBusArn ?? "default bus", href: "/events" };
  if (d.KinesisFirehoseDestination) return { kind: "firehose", icon: ICONS.firehose, target: d.KinesisFirehoseDestination.DeliveryStreamArn ?? "" };
  const dim = d.CloudWatchDestination?.DimensionConfigurations?.[0];
  return { kind: "cloudwatch", icon: ICONS.cloudwatch, target: dim ? `${dim.DimensionName} from ${dim.DimensionValueSource?.toLowerCase().replace("_", " ")} (default ${dim.DefaultDimensionValue})` : "CloudWatch", href: "/cloudwatch" };
}

function defaultsOf(d: EventDestination): DestinationDefaults {
  const dim = d.CloudWatchDestination?.DimensionConfigurations?.[0];
  return {
    name: d.Name,
    kind: describe(d).kind,
    enabled: !!d.Enabled,
    events: d.MatchingEventTypes ?? [],
    topic: d.SnsDestination?.TopicArn,
    bus: d.EventBridgeDestination?.EventBusArn,
    stream: d.KinesisFirehoseDestination?.DeliveryStreamArn,
    role: d.KinesisFirehoseDestination?.IamRoleArn,
    dimension: dim?.DimensionName,
    dimensionSource: dim?.DimensionValueSource,
    dimensionDefault: dim?.DefaultDimensionValue,
  };
}

export default async function ConfigSet({ searchParams }: Props) {
  const { name = "" } = await searchParams;
  const back = { href: "/ses?tab=configsets", label: "Configuration sets" };
  const data = await load(async () => {
    const client = await ses();
    const [set, destinations, snsTopics, firehoses] = await Promise.all([
      client.send(new GetConfigurationSetCommand({ ConfigurationSetName: name })),
      client.send(new GetConfigurationSetEventDestinationsCommand({ ConfigurationSetName: name })).then((r) => r.EventDestinations ?? []),
      topics(),
      streams(),
    ]);
    return { set, destinations, snsTopics, firehoses };
  });
  if (!data.ok) {
    return (
      <Page title={name || "Configuration set"} icon={ICONS.email} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { set, destinations, snsTopics, firehoses } = data.value;
  const sending = set.SendingOptions?.SendingEnabled !== false;
  const suppress = set.SuppressionOptions?.SuppressedReasons;
  return (
    <Page
      title={name}
      icon={ICONS.email}
      back={back}
      actions={
        <>
          <Sheet title="Edit configuration set" label="Edit configuration set" icon={<Pencil size={16} />} testId="edit-config-set">
            <ActionForm action={updateConfigSet.bind(null, name)} submit="Save" testId="edit-config-set">
              <label className="check">
                <input type="checkbox" name="sending" defaultChecked={sending} /> Sending enabled
              </label>
              <label className="check">
                <input type="checkbox" name="reputation" defaultChecked={!!set.ReputationOptions?.ReputationMetricsEnabled} /> Reputation metrics
              </label>
              <div className="form-row">
                <Field label="TLS to the receiving server" member="TlsPolicy">
                  <select name="tls" defaultValue={set.DeliveryOptions?.TlsPolicy ?? "OPTIONAL"}>
                    <option value="OPTIONAL">Optional</option>
                    <option value="REQUIRE">Require</option>
                  </select>
                </Field>
                <Field label="Maximum delivery time" rule={{ type: "integer", min: 300, max: 50400, unit: "seconds" }} member="MaxDeliverySeconds">
                  <input name="maxDelivery" type="number" defaultValue={set.DeliveryOptions?.MaxDeliverySeconds} placeholder="50400" />
                </Field>
              </div>
              <Field label="Custom redirect domain" rule={{ format: "domain" }} member="CustomRedirectDomain">
                <input name="redirectDomain" defaultValue={set.TrackingOptions?.CustomRedirectDomain} placeholder="track.example.com" />
              </Field>
              <input type="hidden" name="wasRedirect" value={set.TrackingOptions?.CustomRedirectDomain ?? ""} />
              <label className="check">
                <input type="checkbox" name="overrideSuppression" defaultChecked={!!suppress} /> Override the account suppression list
              </label>
              <fieldset className="checks">
                <legend>Suppress addresses that</legend>
                <label className="check">
                  <input type="checkbox" name="suppress" value="BOUNCE" defaultChecked={suppress?.includes("BOUNCE")} /> Bounce
                </label>
                <label className="check">
                  <input type="checkbox" name="suppress" value="COMPLAINT" defaultChecked={suppress?.includes("COMPLAINT")} /> Complain
                </label>
              </fieldset>
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteConfigSet.bind(null, name, true)} submit="Delete configuration set" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} testId="delete-config-set" />
        </>
      }
    >
      <Specs
        items={[
          { label: "Sending", icon: <Send size={15} />, value: <Status tone={sending ? "good" : "bad"}>{sending ? "enabled" : "paused"}</Status> },
          { label: "Reputation metrics", icon: <Gauge size={15} />, value: set.ReputationOptions?.ReputationMetricsEnabled ? "On" : "Off" },
          { label: "TLS", icon: <Lock size={15} />, value: set.DeliveryOptions?.TlsPolicy === "REQUIRE" ? "Required" : "Optional" },
          set.DeliveryOptions?.MaxDeliverySeconds && { label: "Max delivery", icon: <Send size={15} />, value: `${set.DeliveryOptions.MaxDeliverySeconds}s` },
          set.TrackingOptions?.CustomRedirectDomain && { label: "Redirect domain", icon: <MousePointerClick size={15} />, value: set.TrackingOptions.CustomRedirectDomain },
          {
            label: "Suppression",
            icon: <ShieldBan size={15} />,
            value: suppress ? (suppress.length ? `Overrides account: ${suppress.map((r) => r.toLowerCase()).join(", ")}` : "Overrides account: none") : "Account settings",
          },
        ]}
      />
      <Section
        title="Event destinations"
        count={destinations.length}
        plain
        actions={
          <Sheet title="Add event destination" label="Add destination" icon={<Plus size={16} />} testId="add-destination">
            <ActionForm action={createEventDestination.bind(null, name)} submit="Add" testId="add-destination">
              <DestinationFields defaults={{ kind: "sns", enabled: true, events: ["SEND", "DELIVERY", "BOUNCE", "COMPLAINT"] }} topics={snsTopics} streams={firehoses} nameRule={{ ...DESTINATION_NAME, taken: destinations.map((d) => d.Name!) }} />
            </ActionForm>
          </Sheet>
        }
      >
        <List
          label="Event destinations"
          empty={<Empty icon={ICONS.email} />}
          rows={destinations.map((d) => {
            const info = describe(d);
            return {
              key: d.Name!,
              icon: <AwsIcon icon={info.icon} size={22} />,
              title: d.Name,
              subtitle: info.target,
              href: info.href,
              meta: (
                <>
                  {(d.MatchingEventTypes ?? []).map((t) => (
                    <Pill key={t}>{t.toLowerCase().replace("_", " ")}</Pill>
                  ))}
                  <Status tone={d.Enabled ? "good" : "neutral"}>{d.Enabled ? "enabled" : "disabled"}</Status>
                </>
              ),
              actions: (
                <>
                  <Sheet title={`Edit ${d.Name}`} label={`Edit ${d.Name}`} icon={<Pencil size={15} />} testId={`edit-destination-${d.Name}`}>
                    <ActionForm action={updateEventDestination.bind(null, name, d.Name!)} submit="Save" testId={`edit-destination-${d.Name}`}>
                      <DestinationFields defaults={defaultsOf(d)} topics={snsTopics} streams={firehoses} nameRule={DESTINATION_NAME} editing />
                    </ActionForm>
                  </Sheet>
                  <ActionForm action={deleteEventDestination.bind(null, name, d.Name!)} submit={`Delete ${d.Name}`} icon={<X size={15} />} tone="danger" confirm={`Delete ${d.Name}?`} />
                </>
              ),
            };
          })}
        />
      </Section>
    </Page>
  );
}

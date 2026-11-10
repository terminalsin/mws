import {
  DescribeLogGroupsCommand,
  DescribeLogStreamsCommand,
} from "@aws-sdk/client-cloudwatch-logs";
import { ListMetricsCommand } from "@aws-sdk/client-cloudwatch";
import { all, bytes, load, when } from "@mws-dashboard/aws";
import { bucketOptions } from "@mws-dashboard/aws/auto";
import {
  ActionForm,
  AutoPick,
  ErrorNotice,
  Facts,
  Field,
  Page,
  Section,
  Segments,
  Sheet,
} from "@mws-dashboard/ui";
import {
  AssociateKmsKey,
  CreateExportTask,
  PutLogEvents,
  PutRetentionPolicy,
} from "@mws-dashboard/ui/model/logs";
import {
  Clock,
  FileSearch,
  KeyRound,
  PenLine,
  Shield,
  ShieldOff,
  Trash2,
  Upload,
} from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import {
  ICONS,
  arnHref,
  cloudwatch,
  groupHref,
  logs,
  sourceIcon,
} from "../../../lib/clients";
import { keyOptions, subscriptionTargets } from "../../../lib/destinations";
import { clockNow } from "../../../lib/events";
import { RETENTION, retentionLabel } from "../../../lib/retention";
import {
  deleteGroup,
  exportToS3,
  setDeletionProtection,
  setKmsKey,
  setRetention,
  writeEvent,
} from "../actions";
import {
  EventsTab,
  MetricFiltersTab,
  StreamsTab,
  SubscriptionsTab,
  TagsTab,
  type Search,
} from "./tabs";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

type Props = { searchParams: Promise<Search> };

export async function generateMetadata({
  searchParams,
}: Props): Promise<Metadata> {
  return { title: (await searchParams).name ?? "Log group" };
}

const TABS = ["events", "streams", "metric-filters", "subscriptions", "tags"];

export default async function LogGroup({ searchParams }: Props) {
  const search = await searchParams;
  const { name = "", stream } = search;
  const tab = TABS.includes(search.tab ?? "") ? search.tab! : "events";
  const back = { href: "/logs", label: "Log groups" };
  const client = await logs();
  const [group, streams, now, keys] = await Promise.all([
    load(async () =>
      (
        await client.send(
          new DescribeLogGroupsCommand({ logGroupNamePrefix: name }),
        )
      ).logGroups?.find((g) => g.logGroupName === name),
    ),
    load(
      async () =>
        (
          await client.send(
            new DescribeLogStreamsCommand({
              logGroupName: name,
              orderBy: "LastEventTime",
              descending: true,
              limit: 50,
            }),
          )
        ).logStreams ?? [],
    ),
    clockNow(),
    keyOptions(),
  ]);
  const icon = sourceIcon(name) ?? ICONS.logs;
  if (!group.ok || !group.value) {
    return (
      <Page title={name} icon={icon} back={back}>
        <ErrorNotice
          error={
            group.ok
              ? `The specified log group does not exist: ${name}`
              : group.error
          }
        />
      </Page>
    );
  }
  const g = group.value;
  const arn = g.logGroupArn ?? g.arn ?? "";
  const streamNames = streams.ok
    ? streams.value.map((s) => s.logStreamName!)
    : [];
  const base = groupHref(name);
  const lambda = name.match(/^\/aws\/lambda\/(.+)$/)?.[1];
  let body;
  if (tab === "streams") body = <StreamsTab name={name} token={search.token} />;
  else if (tab === "metric-filters") {
    const ns = await load(async () => {
      const c = await cloudwatch();
      return all(
        (NextToken) => c.send(new ListMetricsCommand({ NextToken })),
        (r) => r.Metrics?.map((m) => m.Namespace!),
        (r) => r.NextToken,
      );
    });
    body = (
      <MetricFiltersTab
        name={name}
        namespaces={
          ns.ok
            ? [...new Set(ns.value)].filter((n) => !n.startsWith("AWS/")).sort()
            : []
        }
      />
    );
  } else if (tab === "subscriptions")
    body = (
      <SubscriptionsTab
        name={name}
        arn={arn}
        targets={await subscriptionTargets()}
      />
    );
  else if (tab === "tags") body = <TagsTab arn={arn.replace(/:\*$/, "")} />;
  else
    body = (
      <EventsTab
        name={name}
        search={search}
        now={now}
        multiStream={streamNames.length > 1}
      />
    );
  const buckets = tab === "events" ? await bucketOptions() : [];
  return (
    <Page
      title={name}
      icon={icon}
      back={back}
      subtitle={arn.replace(/:\*$/, "") || undefined}
      actions={
        <>
          <Sheet
            title="Write event"
            label="Write event"
            icon={<PenLine size={16} />}
            testId="write-event"
          >
            <ActionForm
              action={writeEvent.bind(null, name)}
              submit="Write"
              testId="write-event"
            >
              <Field
                label="Stream"
                rule={PutLogEvents.logStreamName}
                known={streamNames}
                generate="name"
              >
                <input name="stream" defaultValue={stream ?? "console"} />
              </Field>
              <Field
                label="Message"
                rule={PutLogEvents.logEvents.item!.fields!.message}
              >
                <textarea name="message" rows={3} />
              </Field>
            </ActionForm>
          </Sheet>
          <Link
            className="icon-button plain"
            href={`/logs/insights?${new URLSearchParams({ groups: name })}`}
            aria-label="Query in Logs Insights"
            title="Query in Logs Insights"
          >
            <FileSearch size={16} aria-hidden />
          </Link>
          <Sheet
            title="Retention"
            label="Change retention"
            icon={<Clock size={16} />}
            testId="retention"
          >
            <ActionForm
              action={setRetention.bind(null, name)}
              submit="Save"
              testId="retention"
            >
              <Field
                label="Retention"
                rule={PutRetentionPolicy.retentionInDays}
              >
                <select name="retention" defaultValue={g.retentionInDays ?? 0}>
                  {RETENTION.map((d) => (
                    <option key={d} value={d}>
                      {retentionLabel(d)}
                    </option>
                  ))}
                </select>
              </Field>
            </ActionForm>
          </Sheet>
          <Sheet
            title="Encryption key"
            label="KMS key"
            icon={<KeyRound size={16} />}
            testId="kms-key"
          >
            <ActionForm
              action={setKmsKey.bind(null, name)}
              submit="Save"
              testId="kms-key"
            >
              <Field
                label="KMS key ARN"
                rule={{
                  ...AssociateKmsKey.kmsKeyId,
                  required: false,
                  format: "arn",
                }}
                known={keys.arns}
                hint="Empty removes the key"
              >
                <ResourcePicker kind="kms-key" name="kms" exclude="AWS managed" defaultValue={g.kmsKeyId} />
              </Field>
              <datalist id="kms-keys">
                {Object.entries(keys.aliases).map(([alias, keyArn]) => (
                  <option key={alias} value={keyArn}>
                    {alias}
                  </option>
                ))}
              </datalist>
            </ActionForm>
          </Sheet>
          <Sheet
            title="Export to Amazon S3"
            label="Export to S3"
            icon={<Upload size={16} />}
            testId="export-logs"
          >
            <ActionForm
              action={exportToS3.bind(null, name)}
              submit="Export"
              testId="export-logs"
            >
              <AutoPick
                name="bucket"
                label="Bucket"
                creates="logs-export-<account>-<region>"
                options={buckets}
                testId="export-bucket"
              />
              <Field label="Prefix" rule={CreateExportTask.destinationPrefix}>
                <input name="prefix" defaultValue="exportedlogs" />
              </Field>
              <Field
                label="Last hours"
                rule={{ type: "integer", min: 1, max: 24 * 365 }}
              >
                <input name="hours" type="number" defaultValue={24} />
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm
            action={setDeletionProtection.bind(
              null,
              name,
              !g.deletionProtectionEnabled,
            )}
            submit={
              g.deletionProtectionEnabled
                ? "Turn off deletion protection"
                : "Turn on deletion protection"
            }
            icon={
              g.deletionProtectionEnabled ? (
                <ShieldOff size={16} />
              ) : (
                <Shield size={16} />
              )
            }
            testId="deletion-protection"
          />
          <ActionForm
            action={deleteGroup.bind(null, name)}
            submit="Delete log group"
            icon={<Trash2 size={16} />}
            tone="danger"
            confirm={`Delete ${name} and all its events?`}
            testId="delete-log-group"
          />
        </>
      }
    >
      <Facts
        items={[
          ["Retention", retentionLabel(g.retentionInDays ?? 0)],
          ["Stored", bytes(g.storedBytes ?? 0)],
          g.logGroupClass &&
            g.logGroupClass !== "STANDARD" && [
              "Class",
              g.logGroupClass === "INFREQUENT_ACCESS"
                ? "Infrequent Access"
                : g.logGroupClass,
            ],
          g.kmsKeyId && [
            "KMS key",
            <Link key="k" href={arnHref(g.kmsKeyId) ?? "#"}>
              {g.kmsKeyId.split("/").pop()}
            </Link>,
          ],
          g.deletionProtectionEnabled && [
            "Deletion protection",
            <Shield key="p" size={14} aria-label="On" />,
          ],
          g.dataProtectionStatus && ["Data protection", g.dataProtectionStatus],
          lambda && [
            "Function",
            <Link key="f" href={`/lambda/${encodeURIComponent(lambda)}`}>
              {lambda}
            </Link>,
          ],
          ["Created", when(g.creationTime)],
        ]}
      />
      <Segments
        label="Log group"
        items={[
          { label: "Log events", href: base, active: tab === "events" },
          {
            label: "Log streams",
            href: `${base}&tab=streams`,
            active: tab === "streams",
          },
          {
            label: "Metric filters",
            href: `${base}&tab=metric-filters`,
            active: tab === "metric-filters",
            count: g.metricFilterCount || undefined,
          },
          {
            label: "Subscription filters",
            href: `${base}&tab=subscriptions`,
            active: tab === "subscriptions",
          },
          { label: "Tags", href: `${base}&tab=tags`, active: tab === "tags" },
        ]}
      />
      <Section plain>{body}</Section>
    </Page>
  );
}

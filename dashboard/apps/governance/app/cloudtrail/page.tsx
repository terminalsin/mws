import { DescribeTrailsCommand, GetTrailStatusCommand, LookupEventsCommand, type LookupAttributeKey } from "@aws-sdk/client-cloudtrail";
import { ago, load } from "@mws-dashboard/aws";
import { bucketOptions } from "@mws-dashboard/aws/auto";
import { ActionForm, AutoPick, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status, SERVICES } from "@mws-dashboard/ui";
import { Pause, Play, Search, Trash2, User } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, cloudtrail } from "../../lib/clients";
import { createTrail, deleteTrail, setLogging } from "./actions";

export const metadata: Metadata = { title: "CloudTrail" };

type Props = { searchParams: Promise<{ tab?: string; key?: string; value?: string }> };

/** The service an event came from, for its icon ("s3.amazonaws.com"). */
function sourceIcon(source: string | undefined) {
  const id = source?.split(".")[0] ?? "";
  return SERVICES.find((s) => s.id === id || s.endpoints.includes(id))?.icon ?? ICONS.cloudtrail;
}

const READ = /^(Get|List|Describe|Head|Lookup|Select|Search|Query|Scan|BatchGet)/;

export default async function CloudTrail({ searchParams }: Props) {
  const { tab = "events", key = "", value = "" } = await searchParams;
  const client = await cloudtrail();
  if (tab === "trails") {
    const trails = await load(async () => {
      const list = (await client.send(new DescribeTrailsCommand({}))).trailList ?? [];
      return Promise.all(list.map(async (t) => ({ t, status: await client.send(new GetTrailStatusCommand({ Name: t.TrailARN })).catch(() => undefined) })));
    });
    const buckets = await bucketOptions();
    const create = (
      <Sheet title="Create trail" label="Create trail" testId="create-trail">
        <ActionForm action={createTrail} submit="Create trail" testId="create-trail">
          <Field label="Trail name">
            <input name="name" required autoFocus />
          </Field>
          <AutoPick name="bucket" label="S3 bucket" creates="aws-cloudtrail-logs-<account>-<region>" options={buckets} testId="trail-bucket" />
          <label className="check">
            <input type="checkbox" name="multi" defaultChecked /> All Regions
          </label>
        </ActionForm>
      </Sheet>
    );
    return (
      <Page title="Trails" actions={create}>
        {trails.ok ? (
          <List
            label="Trails"
            empty={<Empty icon={ICONS.cloudtrail} action={create} />}
            rows={trails.value.map(({ t, status }) => ({
              key: t.TrailARN!,
              icon: <AwsIcon icon={ICONS.cloudtrail} size={24} />,
              title: t.Name,
              subtitle: `s3://${t.S3BucketName}/${t.S3KeyPrefix ?? ""}`,
              meta: (
                <>
                  {t.IsMultiRegionTrail && <Pill>All Regions</Pill>}
                  {t.IsOrganizationTrail && <Pill tone="info">Organization</Pill>}
                  <Status tone={status?.IsLogging ? "good" : "neutral"}>{status?.IsLogging ? "Logging" : "Off"}</Status>
                  {status?.LatestDeliveryTime && <span>{ago(status.LatestDeliveryTime)}</span>}
                </>
              ),
              actions: (
                <>
                  <ActionForm action={setLogging.bind(null, t.Name!, !status?.IsLogging)} submit={status?.IsLogging ? `Stop logging ${t.Name}` : `Start logging ${t.Name}`} icon={status?.IsLogging ? <Pause size={15} /> : <Play size={15} />} />
                  <ActionForm action={deleteTrail.bind(null, t.Name!)} submit={`Delete ${t.Name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${t.Name}?`} />
                </>
              ),
            }))}
          />
        ) : (
          <ErrorNotice error={trails.error} />
        )}
      </Page>
    );
  }
  const events = await load(async () => (await client.send(new LookupEventsCommand({ MaxResults: 50, LookupAttributes: key && value ? [{ AttributeKey: key as LookupAttributeKey, AttributeValue: value }] : undefined }))).Events ?? []);
  return (
    <Page title="Event history">
      <form className="search-page-form filter-bar" action="/governance/cloudtrail">
        <select name="key" defaultValue={key || "EventName"} aria-label="Lookup attribute">
          {["EventName", "Username", "EventSource", "ResourceName", "ResourceType", "AccessKeyId", "ReadOnly"].map((k) => (
            <option key={k} value={k}>
              {k.replace(/([a-z])([A-Z])/g, "$1 $2")}
            </option>
          ))}
        </select>
        <input name="value" defaultValue={value} placeholder="Value" aria-label="Lookup value" />
        <button className="icon-button" aria-label="Look up">
          <Search size={16} />
        </button>
      </form>
      {events.ok ? (
        <List
          label="Events"
          empty={<Empty icon={ICONS.cloudtrail} />}
          rows={events.value.map((e) => {
            let error: string | undefined;
            try {
              error = JSON.parse(e.CloudTrailEvent ?? "{}").errorCode;
            } catch {
              // not JSON
            }
            return {
              key: e.EventId!,
              icon: <AwsIcon icon={sourceIcon(e.EventSource)} size={22} />,
              title: e.EventName,
              subtitle: (
                <>
                  <User size={11} aria-hidden /> {e.Username ?? "—"}
                  {e.Resources?.[0]?.ResourceName ? ` · ${e.Resources[0].ResourceName}` : ""}
                </>
              ),
              meta: (
                <>
                  {error && <Status tone="bad">{error}</Status>}
                  {!READ.test(e.EventName ?? "") && <Pill tone="info">Write</Pill>}
                  <span>{ago(e.EventTime)}</span>
                </>
              ),
            };
          })}
        />
      ) : (
        <ErrorNotice error={events.error} />
      )}
    </Page>
  );
}

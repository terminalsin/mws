import { DescribeTrailsCommand, GetTrailStatusCommand, LookupEventsCommand, type LookupAttributeKey } from "@aws-sdk/client-cloudtrail";
import { ago, describeError, frameInfo, load, region as currentRegion } from "@mws-dashboard/aws";
import { bucketOptions } from "@mws-dashboard/aws/auto";
import { ActionForm, AutoPick, AwsIcon, Empty, ErrorNotice, Field, List, More, Page, Pill, Sheet, Status, SERVICES } from "@mws-dashboard/ui";
import { Pause, Play, Search, Trash2, TriangleAlert, User } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, cloudtrail, eventHref, shadowOf, trailHref } from "../../lib/clients";
import { TRAIL_NAME, parseRecord } from "../../lib/rules";
import { createTrail, deleteTrail, setLogging } from "./actions";

export const metadata: Metadata = { title: "CloudTrail" };

type Params = { tab?: string; key?: string; value?: string; start?: string; end?: string; category?: string; token?: string };
type Props = { searchParams: Promise<Params> };

/** The service an event came from, for its icon ("s3.amazonaws.com"). */
function sourceIcon(source: string | undefined) {
  const id = source?.split(".")[0] ?? "";
  return SERVICES.find((s) => s.id === id || s.endpoints.includes(id))?.icon ?? ICONS.cloudtrail;
}

const ATTRIBUTES = ["EventName", "Username", "EventSource", "ResourceName", "ResourceType", "AccessKeyId", "ReadOnly", "EventId"];

/** A `datetime-local` value, read as UTC. */
const utc = (v: string | undefined) => {
  if (!v) return undefined;
  const d = new Date(/Z|[+-]\d\d:?\d\d$/.test(v) ? v : `${v}Z`);
  return Number.isNaN(d.getTime()) ? undefined : d;
};

function href(p: Params) {
  const q = new URLSearchParams(Object.entries(p).filter((e): e is [string, string] => !!e[1]));
  return `/cloudtrail${q.size ? `?${q}` : ""}`;
}

async function Trails() {
  const client = await cloudtrail();
  const [region, me] = await Promise.all([currentRegion(), frameInfo()]);
  const trails = await load(async () => {
    const list = (await client.send(new DescribeTrailsCommand({ includeShadowTrails: true }))).trailList ?? [];
    return Promise.all(
      list.map(async (t) => {
        const status = await client.send(new GetTrailStatusCommand({ Name: t.TrailARN })).then(
          (s) => ({ ok: true as const, s }),
          (e) => ({ ok: false as const, error: describeError(e) }),
        );
        return { t, status, shadow: shadowOf(t, region, me.account) };
      }),
    );
  });
  // Start on the bucket CloudTrail delivered to before, else on creating one:
  // an arbitrary existing bucket lacks the policy CloudTrail needs.
  const auto = `aws-cloudtrail-logs-${me.account}-${region}`;
  const all = await bucketOptions();
  const preferred = all.find((b) => b.value === auto)?.value ?? all.find((b) => /cloudtrail/i.test(b.value))?.value;
  const buckets = preferred ? all : [];
  const create = (
    <Sheet title="Create trail" label="Create trail" testId="create-trail">
      <ActionForm action={createTrail} submit="Create trail" testId="create-trail">
        <Field label="Trail name" rule={TRAIL_NAME} taken={trails.ok ? trails.value.map(({ t }) => t.Name!) : []} unique>
          <input name="name" required maxLength={128} autoFocus />
        </Field>
        <AutoPick name="bucket" label="S3 bucket" creates={auto} preferred={preferred} options={buckets} testId="trail-bucket" />
        <label className="check">
          <input type="checkbox" name="multi" defaultChecked /> All Regions
        </label>
        <label className="check">
          <input type="checkbox" name="validation" defaultChecked /> Log file validation
        </label>
        <label className="check">
          <input type="checkbox" name="start" defaultChecked /> Start logging
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
          rows={trails.value.map(({ t, status, shadow }) => {
            const logging = status.ok && status.s.IsLogging;
            return {
              key: t.TrailARN!,
              icon: <AwsIcon icon={ICONS.cloudtrail} size={24} />,
              title: t.Name,
              subtitle: `s3://${t.S3BucketName}/${t.S3KeyPrefix ?? ""}`,
              href: trailHref(t.TrailARN!),
              meta: (
                <>
                  {t.IsMultiRegionTrail && <Pill>All Regions</Pill>}
                  {t.IsOrganizationTrail && <Pill tone="info">Organization</Pill>}
                  {shadow && <Pill title="Change it from its home Region or owner account">{shadow}</Pill>}
                  {status.ok ? (
                    <>
                      {status.s.LatestDeliveryError && (
                        <Pill tone="bad" icon={<TriangleAlert size={12} aria-hidden />} title={status.s.LatestDeliveryError}>
                          Delivery failing
                        </Pill>
                      )}
                      <Status tone={logging ? "good" : "neutral"}>{logging ? "Logging" : "Off"}</Status>
                      {status.s.LatestDeliveryTime && <span>{ago(status.s.LatestDeliveryTime)}</span>}
                    </>
                  ) : (
                    <Pill tone="bad" title={status.error}>
                      Status unavailable
                    </Pill>
                  )}
                </>
              ),
              actions: shadow ? undefined : (
                <>
                  {status.ok && (
                    <ActionForm
                      action={setLogging.bind(null, t.TrailARN!, !logging)}
                      submit={logging ? `Stop logging ${t.Name}` : `Start logging ${t.Name}`}
                      icon={logging ? <Pause size={15} /> : <Play size={15} />}
                    />
                  )}
                  <ActionForm action={deleteTrail.bind(null, t.TrailARN!, false)} submit={`Delete ${t.Name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${t.Name}?`} />
                </>
              ),
            };
          })}
        />
      ) : (
        <ErrorNotice error={trails.error} />
      )}
    </Page>
  );
}

export default async function CloudTrail({ searchParams }: Props) {
  const params = await searchParams;
  if (params.tab === "trails") return <Trails />;
  const { key = "", value = "", start, end, category, token } = params;
  const insights = category === "insight";
  const client = await cloudtrail();
  const events = await load(() =>
    client.send(
      new LookupEventsCommand({
        MaxResults: 50,
        NextToken: token,
        StartTime: utc(start),
        EndTime: utc(end),
        EventCategory: insights ? "insight" : undefined,
        LookupAttributes: key && value ? [{ AttributeKey: key as LookupAttributeKey, AttributeValue: value }] : undefined,
      }),
    ),
  );
  const list = events.ok ? (events.value.Events ?? []) : [];
  return (
    <Page title={insights ? "Insights" : "Event history"}>
      <form className="search-page-form filter-bar" action="/cloudtrail" data-testid="lookup-events">
        <select name="category" defaultValue={category ?? ""} aria-label="Event category">
          <option value="">Management events</option>
          <option value="insight">Insights events</option>
        </select>
        <select name="key" defaultValue={key || "EventName"} aria-label="Lookup attribute">
          {ATTRIBUTES.map((k) => (
            <option key={k} value={k}>
              {k.replace(/([a-z])([A-Z])/g, "$1 $2")}
            </option>
          ))}
        </select>
        <input name="value" defaultValue={value} placeholder="Value" aria-label="Lookup value" />
        <input name="start" type="datetime-local" defaultValue={start} aria-label="From (UTC)" title="From (UTC)" />
        <input name="end" type="datetime-local" defaultValue={end} aria-label="To (UTC)" title="To (UTC)" />
        <button className="icon-button" aria-label="Look up">
          <Search size={16} />
        </button>
      </form>
      {events.ok ? (
        <>
          <List
            label="Events"
            empty={<Empty icon={ICONS.cloudtrail} />}
            rows={list.map((e) => {
              const record = parseRecord(e.CloudTrailEvent);
              const error = record.errorCode as string | undefined;
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
                href: `${eventHref(e.EventId!)}${insights ? "&category=insight" : ""}`,
                meta: (
                  <>
                    {error && <Status tone="bad">{error}</Status>}
                    {record.readOnly === false && <Pill tone="info">Write</Pill>}
                    <span title={e.EventTime?.toISOString()}>{ago(e.EventTime)}</span>
                  </>
                ),
              };
            })}
          />
          <More shown={list.length} noun="events" href={events.value.NextToken ? href({ ...params, token: events.value.NextToken }) : undefined} />
        </>
      ) : (
        <ErrorNotice error={events.error} />
      )}
    </Page>
  );
}

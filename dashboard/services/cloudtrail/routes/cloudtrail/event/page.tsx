import { LookupEventsCommand } from "@aws-sdk/client-cloudtrail";
import { load, when } from "@mws-dashboard/aws";
import { CodeBlock, ErrorNotice, Facts, Page, Pill, Section, Specs, Status, SERVICES } from "@mws-dashboard/ui";
import { Clock, Globe, KeyRound, User } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, cloudtrail } from "../../../lib/clients";
import { parseRecord } from "../../../lib/rules";

type Props = { searchParams: Promise<{ id?: string; category?: string }> };

export const metadata: Metadata = { title: "Event" };

type Identity = { type?: string; arn?: string; userName?: string; accountId?: string; accessKeyId?: string; principalId?: string; invokedBy?: string; sessionContext?: { sessionIssuer?: { arn?: string; userName?: string; type?: string } } };

/** A console page for a resource a record names, where one exists. */
function resourceHref(type: string | undefined, name: string | undefined): string | undefined {
  if (!name) return undefined;
  const tail = name.split(/[:/]/).pop() ?? name;
  switch (type) {
    case "AWS::S3::Bucket":
      return `/s3/${encodeURIComponent(tail)}`;
    case "AWS::S3::Object": {
      const path = name.replace(/^arn:aws:s3:::/, "");
      const slash = path.indexOf("/");
      return slash > 0 ? `/s3/${encodeURIComponent(path.slice(0, slash))}/object?key=${encodeURIComponent(path.slice(slash + 1))}` : undefined;
    }
    case "AWS::IAM::Role":
      return `/iam/roles/${encodeURIComponent(tail)}`;
    case "AWS::IAM::User":
      return `/iam/users/${encodeURIComponent(tail)}`;
    case "AWS::Lambda::Function":
      return `/lambda/${encodeURIComponent(tail)}`;
    case "AWS::SQS::Queue":
      return `/sqs/${encodeURIComponent(tail)}`;
    case "AWS::SNS::Topic":
      return name.startsWith("arn:") ? `/sns/topic?arn=${encodeURIComponent(name)}` : undefined;
    case "AWS::KMS::Key":
      return `/kms/key?id=${encodeURIComponent(tail)}`;
    case "AWS::CloudTrail::Trail":
      return name.startsWith("arn:") ? `/cloudtrail/trail?arn=${encodeURIComponent(name)}` : undefined;
    default:
      return undefined;
  }
}

function identityHref(u: Identity | undefined): string | undefined {
  if (!u) return undefined;
  if (u.type === "IAMUser" && u.userName) return `/iam/users/${encodeURIComponent(u.userName)}`;
  const issuer = u.sessionContext?.sessionIssuer;
  if (u.type === "AssumedRole" && issuer?.type === "Role" && issuer.userName) return `/iam/roles/${encodeURIComponent(issuer.userName)}`;
  return undefined;
}

const json = (v: unknown) => (v == null ? null : JSON.stringify(v));

export default async function EventPage({ searchParams }: Props) {
  const { id = "", category } = await searchParams;
  const back = { href: category === "insight" ? "/cloudtrail?category=insight" : "/cloudtrail", label: "Event history" };
  const found = await load(async () => {
    const client = await cloudtrail();
    const find = (insight: boolean) =>
      client
        .send(new LookupEventsCommand({ LookupAttributes: [{ AttributeKey: "EventId", AttributeValue: id }], EventCategory: insight ? "insight" : undefined }))
        .then((r) => r.Events?.[0]);
    return (await find(category === "insight")) ?? (category === "insight" ? undefined : await find(true));
  });
  if (!found.ok || !found.value) {
    return (
      <Page title={id} icon={ICONS.cloudtrail} back={back}>
        <ErrorNotice error={found.ok ? "No event with this ID in the last 90 days of this Region." : found.error} />
      </Page>
    );
  }
  const e = found.value;
  const r = parseRecord(e.CloudTrailEvent);
  const u = r.userIdentity as Identity | undefined;
  const source = e.EventSource?.split(".")[0] ?? "";
  const icon = SERVICES.find((s) => s.id === source || s.endpoints.includes(source))?.icon ?? ICONS.cloudtrail;
  const error = r.errorCode as string | undefined;
  const who = identityHref(u);
  return (
    <Page title={e.EventName} icon={icon} back={back} subtitle={e.EventId}>
      <Specs
        items={[
          { label: "Time", icon: <Clock size={15} />, value: when(e.EventTime) },
          { label: "User", icon: <User size={15} />, value: who ? <Link href={who}>{e.Username ?? u?.arn}</Link> : (e.Username ?? u?.arn ?? u?.invokedBy ?? "—") },
          r.sourceIPAddress ? { label: "Source IP", icon: <Globe size={15} />, value: String(r.sourceIPAddress) } : null,
          e.AccessKeyId ? { label: "Access key", icon: <KeyRound size={15} />, value: <code>{e.AccessKeyId}</code> } : null,
        ]}
      />
      {error && <ErrorNotice error={`${error}${r.errorMessage ? `: ${r.errorMessage}` : ""}`} />}
      <Section title="Details">
        <Facts
          items={[
            ["Event source", e.EventSource],
            ["Region", r.awsRegion as string],
            ["Type", r.eventType as string],
            r.readOnly !== undefined && ["Read only", <Pill tone={r.readOnly ? "neutral" : "info"}>{r.readOnly ? "Read" : "Write"}</Pill>],
            ["Identity", [u?.type, u?.arn].filter(Boolean).join(" · ")],
            u?.accountId && ["Account", u.accountId],
            r.userAgent ? ["User agent", <code>{String(r.userAgent)}</code>] : null,
            r.requestID ? ["Request ID", <code>{String(r.requestID)}</code>] : null,
            r.eventCategory ? ["Category", String(r.eventCategory)] : null,
            !error && ["Outcome", <Status tone="good">Succeeded</Status>],
          ]}
        />
      </Section>
      {(e.Resources ?? []).length > 0 && (
        <Section title="Resources" count={e.Resources!.length}>
          <Facts
            items={e.Resources!.map((res) => {
              const href = resourceHref(res.ResourceType, res.ResourceName);
              return [res.ResourceType ?? "Resource", href ? <Link href={href}>{res.ResourceName}</Link> : res.ResourceName];
            })}
          />
        </Section>
      )}
      {r.requestParameters != null && (
        <Section title="Request parameters">
          <CodeBlock value={json(r.requestParameters)} label="Request parameters" />
        </Section>
      )}
      {r.responseElements != null && (
        <Section title="Response elements">
          <CodeBlock value={json(r.responseElements)} label="Response elements" />
        </Section>
      )}
      {r.insightDetails != null && (
        <Section title="Insight details">
          <CodeBlock value={json(r.insightDetails)} label="Insight details" />
        </Section>
      )}
      <details>
        <summary>Event record</summary>
        <CodeBlock value={e.CloudTrailEvent} label="Event record" />
      </details>
    </Page>
  );
}

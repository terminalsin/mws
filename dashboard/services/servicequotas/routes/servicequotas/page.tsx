import {
  GetQuotaUtilizationReportCommand,
  ListAWSDefaultServiceQuotasCommand,
  ListRequestedServiceQuotaChangeHistoryCommand,
  ListServiceQuotasCommand,
  ListServicesCommand,
} from "@aws-sdk/client-service-quotas";
import { ago, all, load, region } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Facts, List, More, Page, Pill, Segments, Sheet, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { ArrowUp, Bot, Gauge, Globe } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, quotas } from "../../lib/clients";
import { IncreaseFields } from "../../lib/increase-fields";
import { openRequests, statusWord, tone, usage, utilization } from "../../lib/quotas";
import { requestIncrease, startUtilizationReport } from "./actions";
import { iconOf, requestRow } from "./rows";

export const metadata: Metadata = { title: "Service Quotas" };

type Props = { searchParams: Promise<{ tab?: string; service?: string; token?: string; status?: string; report?: string }> };

const PAGE = 50;

const links = (
  <>
    <Link className="icon-button plain" href="/servicequotas?tab=utilization" aria-label="Quota utilization" title="Quota utilization">
      <Gauge size={16} aria-hidden />
    </Link>
    <Link className="icon-button plain" href="/servicequotas/automatic" aria-label="Automatic management" title="Automatic management">
      <Bot size={16} aria-hidden />
    </Link>
  </>
);

export default async function Quotas({ searchParams }: Props) {
  const { tab = "services", service, token, status, report } = await searchParams;
  const client = await quotas();
  const where = await region();

  if (service) {
    const list = await load(async () => {
      const [applied, defaults, open] = await Promise.all([
        all((NextToken) => client.send(new ListServiceQuotasCommand({ ServiceCode: service, NextToken })), (r) => r.Quotas, (r) => r.NextToken),
        all((NextToken) => client.send(new ListAWSDefaultServiceQuotasCommand({ ServiceCode: service, NextToken })), (r) => r.Quotas, (r) => r.NextToken),
        openRequests(service),
      ]);
      // Rows are every quota either list knows, applied values first.
      const byCode = new Map(defaults.map((q) => [q.QuotaCode, q]));
      const codes = [...new Set([...defaults.map((q) => q.QuotaCode!), ...applied.map((q) => q.QuotaCode!)])];
      const appliedBy = new Map(applied.map((q) => [q.QuotaCode, q]));
      const used = await usage([...appliedBy.values(), ...defaults.filter((d) => !appliedBy.has(d.QuotaCode))]).catch(() => new Map<string, number>());
      return codes.map((code) => ({ d: byCode.get(code), applied: appliedBy.get(code), open: open.get(code), used: used.get(code) }));
    });
    const name = list.ok ? (list.value[0]?.d?.ServiceName ?? list.value[0]?.applied?.ServiceName ?? service) : service;
    return (
      <Page title={name} icon={iconOf(service)} back={{ href: "/servicequotas", label: "AWS services" }} actions={links}>
        {list.ok ? (
          <>
            <LiveRefresh when={list.value.some((q) => q.open?.Status === "PENDING")} />
            <List
              label="Quotas"
              empty={<Empty icon={ICONS.quotas} />}
              rows={list.value.map(({ d, applied, open, used }) => {
                const q = (applied ?? d)!;
                const value = applied?.Value ?? d?.Value;
                const raised = applied && d && applied.Value !== d.Value;
                const pct = utilization(used, value);
                return {
                  key: q.QuotaCode!,
                  title: q.QuotaName,
                  subtitle: q.QuotaCode,
                  href: `/servicequotas/quota?service=${service}&code=${q.QuotaCode}`,
                  meta: (
                    <>
                      {q.GlobalQuota && <Globe size={13} aria-label="Global quota" />}
                      {open && (
                        <Status tone="info">{`${statusWord(open.Status)} → ${open.DesiredValue}`}</Status>
                      )}
                      {pct !== undefined && (
                        <Pill tone={tone(pct)} title={`Using ${used}`}>
                          {pct}%
                        </Pill>
                      )}
                      {raised && <span className="muted">default {d?.Value}</span>}
                      <Pill tone={raised ? "info" : "neutral"}>{value}</Pill>
                      {q.Unit && q.Unit !== "None" && <span>{q.Unit}</span>}
                    </>
                  ),
                  actions:
                    q.Adjustable && !open ? (
                      <Sheet title={`Request increase: ${q.QuotaName}`} label={`Request increase ${q.QuotaCode}`} icon={<ArrowUp size={15} />} testId={`increase-${q.QuotaCode}`}>
                        <ActionForm action={requestIncrease.bind(null, service, q.QuotaCode!)} submit="Request" testId={`increase-${q.QuotaCode}`}>
                          <IncreaseFields value={value ?? 0} />
                        </ActionForm>
                      </Sheet>
                    ) : undefined,
                };
              })}
            />
          </>
        ) : (
          <ErrorNotice error={list.error} />
        )}
      </Page>
    );
  }

  if (tab === "requests") {
    const history = await load(async () => {
      const r = await client.send(new ListRequestedServiceQuotaChangeHistoryCommand({ NextToken: token, MaxResults: PAGE, Status: (status || undefined) as "PENDING" | undefined }));
      return { items: r.RequestedQuotas ?? [], next: r.NextToken };
    });
    const href = (s: string | undefined) => `/servicequotas?tab=requests${s ? `&status=${s}` : ""}`;
    return (
      <Page title="Quota request history" actions={links}>
        <Segments
          label="Status"
          items={[
            { label: "All", href: href(undefined), active: !status },
            { label: "Pending", href: href("PENDING"), active: status === "PENDING" },
            { label: "Case opened", href: href("CASE_OPENED"), active: status === "CASE_OPENED" },
            { label: "Approved", href: href("APPROVED"), active: status === "APPROVED" },
            { label: "Denied", href: href("DENIED"), active: status === "DENIED" },
          ]}
        />
        {history.ok ? (
          <>
            <LiveRefresh when={history.value.items.some((r) => r.Status === "PENDING")} />
            <List label="Requests" empty={<Empty icon={ICONS.quotas} />} rows={history.value.items.map((r) => requestRow(r))} />
            <More
              shown={history.value.items.length}
              noun="requests"
              href={history.value.next ? `${href(status)}&token=${encodeURIComponent(history.value.next)}` : undefined}
            />
          </>
        ) : (
          <ErrorNotice error={history.error} />
        )}
      </Page>
    );
  }

  if (tab === "utilization") {
    const data = report
      ? await load(async () => {
          const pages = await all(
            (NextToken) => client.send(new GetQuotaUtilizationReportCommand({ ReportId: report, NextToken })),
            (r) => [r],
            (r) => r.NextToken,
          );
          return { status: pages[0]?.Status, generated: pages[0]?.GeneratedAt, error: pages[0]?.ErrorMessage, quotas: pages.flatMap((p) => p.Quotas ?? []) };
        })
      : null;
    const pending = data?.ok && (data.value.status === "PENDING" || data.value.status === "IN_PROGRESS");
    return (
      <Page
        title="Quota utilization"
        back={{ href: "/servicequotas", label: "AWS services" }}
        actions={<ActionForm action={startUtilizationReport} submit="Generate report" icon={<Gauge size={16} />} tone="primary" testId="generate-report" />}
      >
        {!data ? (
          <Empty icon={ICONS.quotas} action={<ActionForm action={startUtilizationReport} submit="Generate report" testId="generate-report-empty" />} />
        ) : !data.ok ? (
          <ErrorNotice error={data.error} />
        ) : (
          <>
            <Facts
              items={[
                ["Report", <Status key="s" tone={data.value.status === "COMPLETED" ? "good" : data.value.status === "FAILED" ? "bad" : "info"}>{statusWord(data.value.status)}</Status>],
                data.value.generated && ["Generated", ago(data.value.generated)],
                data.value.error && ["Error", data.value.error],
                ["Region", where],
              ]}
            />
            <LiveRefresh when={!!pending} />
            <List
              label="Utilization"
              empty={<Empty icon={ICONS.quotas}>{pending ? undefined : "No quota with usage"}</Empty>}
              rows={[...data.value.quotas]
                .sort((a, b) => (b.Utilization ?? 0) - (a.Utilization ?? 0))
                .map((q) => ({
                  key: `${q.ServiceCode}:${q.QuotaCode}`,
                  icon: <AwsIcon icon={iconOf(q.ServiceCode)} size={22} />,
                  title: q.QuotaName,
                  subtitle: `${q.ServiceName ?? q.ServiceCode} · ${q.QuotaCode}`,
                  href: `/servicequotas/quota?service=${q.ServiceCode}&code=${q.QuotaCode}`,
                  meta: (
                    <>
                      <Pill tone={tone(q.Utilization)}>{Math.round((q.Utilization ?? 0) * 10) / 10}%</Pill>
                      <span>of {q.AppliedValue ?? q.DefaultValue}</span>
                    </>
                  ),
                }))}
            />
          </>
        )}
      </Page>
    );
  }

  const services = await load(() => all((NextToken) => client.send(new ListServicesCommand({ NextToken })), (r) => r.Services, (r) => r.NextToken));
  return (
    <Page title="AWS services" actions={links}>
      {services.ok ? (
        <div className="tiles compact" aria-label="Services">
          {services.value.map((s) => (
            <Link key={s.ServiceCode} className="tile" href={`/servicequotas?service=${s.ServiceCode}`}>
              <AwsIcon icon={iconOf(s.ServiceCode)} size={28} />
              <span className="tile-name">{s.ServiceName}</span>
            </Link>
          ))}
        </div>
      ) : (
        <ErrorNotice error={services.error} />
      )}
    </Page>
  );
}


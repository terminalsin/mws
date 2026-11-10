import { ListAWSDefaultServiceQuotasCommand, ListRequestedServiceQuotaChangeHistoryCommand, ListServiceQuotasCommand, ListServicesCommand } from "@aws-sdk/client-service-quotas";
import { ago, collect, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status, SERVICES } from "@mws-dashboard/ui";
import { RequestServiceQuotaIncrease } from "@mws-dashboard/ui/model/servicequotas";
import { ArrowUp } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, quotas } from "../../lib/clients";
import { requestIncrease } from "./actions";

export const metadata: Metadata = { title: "Service Quotas" };

type Props = { searchParams: Promise<{ tab?: string; service?: string }> };

const iconOf = (code: string | undefined) => SERVICES.find((s) => s.id === code || s.endpoints.includes(code ?? ""))?.icon ?? ICONS.quotas;

export default async function Quotas({ searchParams }: Props) {
  const { tab = "services", service } = await searchParams;
  const client = await quotas();
  if (service) {
    const list = await load(async () => {
      const [applied, defaults] = await Promise.all([
        collect(
          (NextToken) => client.send(new ListServiceQuotasCommand({ ServiceCode: service, NextToken })),
          (r) => r.Quotas,
          (r) => r.NextToken,
        ),
        collect(
          (NextToken) => client.send(new ListAWSDefaultServiceQuotasCommand({ ServiceCode: service, NextToken })),
          (r) => r.Quotas,
          (r) => r.NextToken,
        ),
      ]);
      const byCode = new Map(applied.map((q) => [q.QuotaCode, q]));
      return defaults.map((d) => ({ d, applied: byCode.get(d.QuotaCode) }));
    });
    return (
      <Page title={service} icon={iconOf(service)} back={{ href: "/servicequotas", label: "AWS services" }}>
        {list.ok ? (
          <List
            label="Quotas"
            empty={<Empty icon={ICONS.quotas} />}
            rows={list.value.map(({ d, applied }) => {
              const value = applied?.Value ?? d.Value;
              const raised = applied && applied.Value !== d.Value;
              return {
                key: d.QuotaCode!,
                title: d.QuotaName,
                subtitle: d.QuotaCode,
                meta: (
                  <>
                    {raised && <span className="muted">default {d.Value}</span>}
                    <Pill tone={raised ? "info" : "neutral"}>{value}</Pill>
                    {d.Unit && d.Unit !== "None" && <span>{d.Unit}</span>}
                  </>
                ),
                actions: d.Adjustable ? (
                  <Sheet title={`Request increase: ${d.QuotaName}`} label={`Request increase ${d.QuotaCode}`} icon={<ArrowUp size={15} />} testId={`increase-${d.QuotaCode}`}>
                    <ActionForm action={requestIncrease.bind(null, service, d.QuotaCode!)} submit="Request" testId={`increase-${d.QuotaCode}`}>
                      <Field label="New value" hint={`Now ${value ?? 0}`} rule={{ ...RequestServiceQuotaIncrease.DesiredValue, min: Math.floor(value ?? 0) + 1 }} member="DesiredValue">
                        <input name="value" type="number" step="any" min={Math.floor(value ?? 0) + 1} defaultValue={(value ?? 0) * 2 || 1} required />
                      </Field>
                    </ActionForm>
                  </Sheet>
                ) : undefined,
              };
            })}
          />
        ) : (
          <ErrorNotice error={list.error} />
        )}
      </Page>
    );
  }
  if (tab === "requests") {
    const history = await load(async () => (await client.send(new ListRequestedServiceQuotaChangeHistoryCommand({}))).RequestedQuotas ?? []);
    return (
      <Page title="Quota request history">
        {history.ok ? (
          <List
            label="Requests"
            empty={<Empty icon={ICONS.quotas} />}
            rows={history.value.map((r) => ({
              key: r.Id!,
              icon: <AwsIcon icon={iconOf(r.ServiceCode)} size={22} />,
              title: r.QuotaName,
              subtitle: r.ServiceName,
              href: `/servicequotas?service=${r.ServiceCode}`,
              meta: (
                <>
                  <Pill>→ {r.DesiredValue}</Pill>
                  <Status tone={r.Status === "APPROVED" ? "good" : r.Status === "DENIED" || r.Status === "INVALID_REQUEST" ? "bad" : "warn"}>{r.Status?.toLowerCase().replace(/_/g, " ")}</Status>
                  <span>{ago(r.Created)}</span>
                </>
              ),
            }))}
          />
        ) : (
          <ErrorNotice error={history.error} />
        )}
      </Page>
    );
  }
  const services = await load(async () =>
    collect(
      (NextToken) => client.send(new ListServicesCommand({ NextToken })),
      (r) => r.Services,
      (r) => r.NextToken,
    ),
  );
  return (
    <Page title="AWS services">
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

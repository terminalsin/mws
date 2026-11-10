import type { RequestedServiceQuotaChange } from "@aws-sdk/client-service-quotas";
import { ago } from "@mws-dashboard/aws";
import { AwsIcon, Pill, Status, SERVICES } from "@mws-dashboard/ui";

import { ICONS } from "../../lib/clients";
import { STATUS_TONE, statusWord } from "../../lib/quotas";

export const iconOf = (code: string | undefined) => SERVICES.find((s) => s.id === code || s.endpoints.includes(code ?? ""))?.icon ?? ICONS.quotas;

/** A history row: what was asked, where it stands, linked to its quota. */
export function requestRow(r: RequestedServiceQuotaChange, icon = true) {
  return {
    key: r.Id!,
    icon: icon ? <AwsIcon icon={iconOf(r.ServiceCode)} size={22} /> : undefined,
    title: r.QuotaName,
    subtitle: [r.ServiceName, r.RequestType === "AutomaticManagement" && "automatic", r.CaseId && `case ${r.CaseId}`].filter(Boolean).join(" · "),
    href: `/servicequotas/quota?service=${r.ServiceCode}&code=${r.QuotaCode}`,
    meta: (
      <>
        <Pill>→ {r.DesiredValue}</Pill>
        <Status tone={STATUS_TONE[r.Status!] ?? "neutral"}>{statusWord(r.Status)}</Status>
        <span>{ago(r.Created)}</span>
      </>
    ),
  };
}


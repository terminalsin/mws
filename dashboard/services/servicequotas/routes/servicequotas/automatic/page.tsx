import { GetAutoManagementConfigurationCommand } from "@aws-sdk/client-service-quotas";
import { load } from "@mws-dashboard/aws";
import { ActionForm, ErrorNotice, Facts, Field, List, Page, Section, Sheet, Status } from "@mws-dashboard/ui";
import { Pencil, Play, Square } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, quotas } from "../../../lib/clients";
import { saveAutoManagement, stopAutoManagement } from "../actions";

export const metadata: Metadata = { title: "Automatic management" };

/** Automatic quota management: notify (and raise) as usage nears a quota. */
export default async function Automatic() {
  const back = { href: "/servicequotas", label: "AWS services" };
  const data = await load(async () => (await quotas()).send(new GetAutoManagementConfigurationCommand({})));
  if (!data.ok) {
    return (
      <Page title="Automatic management" icon={ICONS.quotas} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const c = data.value;
  const on = c.OptInStatus === "ENABLED";
  const excluded = Object.entries(c.ExclusionList ?? {});
  const form = (
    <ActionForm action={saveAutoManagement.bind(null, on)} submit={on ? "Save" : "Start"} testId="auto-management">
      <Field label="When usage reaches 80%">
        <select name="type" defaultValue={c.OptInType ?? "NotifyOnly"}>
          <option value="NotifyOnly">Notify only</option>
          <option value="NotifyAndAdjust">Notify and request an increase</option>
        </select>
      </Field>
      <Field label="Excluded quotas" hint="One service per line: ec2=L-1216C47A,L-34B43A08, or a service code alone" format="pairs">
        <textarea
          name="exclude"
          rows={4}
          defaultValue={excluded.map(([s, qs]) => (qs.length ? `${s}=${qs.map((q) => q.QuotaCode).join(",")}` : s)).join("\n")}
        />
      </Field>
    </ActionForm>
  );
  return (
    <Page
      title="Automatic management"
      icon={ICONS.quotas}
      back={back}
      actions={
        <>
          <Sheet title="Automatic management" label={on ? "Edit automatic management" : "Start automatic management"} icon={on ? <Pencil size={16} /> : <Play size={16} />} testId="auto-management">
            {form}
          </Sheet>
          {on && <ActionForm action={stopAutoManagement} submit="Stop automatic management" icon={<Square size={16} />} tone="danger" confirm="Stop automatic management?" testId="stop-auto-management" />}
        </>
      }
    >
      <Facts
        items={[
          ["Status", <Status key="s" tone={on ? "good" : "neutral"}>{on ? "enabled" : "disabled"}</Status>],
          on && ["Action", c.OptInType === "NotifyAndAdjust" ? "Notify and request an increase" : "Notify only"],
          on && c.OptInLevel && ["Level", c.OptInLevel.toLowerCase()],
          c.NotificationArn && ["Notifications", c.NotificationArn],
        ]}
      />
      {excluded.length > 0 && (
        <Section title="Excluded" count={excluded.reduce((n, [, q]) => n + Math.max(q.length, 1), 0)} plain>
          <List
            label="Excluded quotas"
            rows={excluded.flatMap(([service, qs]) =>
              (qs.length ? qs : [{ QuotaCode: undefined, QuotaName: "All quotas" }]).map((q) => ({
                key: `${service}:${q.QuotaCode ?? "*"}`,
                title: q.QuotaName ?? q.QuotaCode,
                subtitle: `${service}${q.QuotaCode ? ` · ${q.QuotaCode}` : ""}`,
                href: q.QuotaCode ? `/servicequotas/quota?service=${service}&code=${q.QuotaCode}` : `/servicequotas?service=${service}`,
              })),
            )}
          />
        </Section>
      )}
    </Page>
  );
}

import { DescribeStandardsCommand, DescribeStandardsControlsCommand, GetEnabledStandardsCommand } from "@aws-sdk/client-securityhub";
import { all, load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { UpdateStandardsControl as Rules } from "@mws-dashboard/ui/model/securityhub";
import { Minus, Power, PowerOff, ShieldCheck } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, securityhub, severity, word } from "../../../lib/clients";
import { controlIcon } from "../../../lib/presets";
import { disableStandard, setControl } from "../actions";

export const metadata: Metadata = { title: "Standard · Security Hub" };

type Props = { searchParams: Promise<{ arn?: string }> };

export default async function Standard({ searchParams }: Props) {
  const { arn = "" } = await searchParams;
  const back = { href: "/securityhub?tab=standards", label: "Security standards" };
  const data = await load(async () => {
    const client = await securityhub();
    const sub = (await client.send(new GetEnabledStandardsCommand({ StandardsSubscriptionArns: [arn] }))).StandardsSubscriptions?.[0];
    if (!sub) throw new Error(`Standard subscription ${arn} not found`);
    const controls = await all(
      (NextToken) => client.send(new DescribeStandardsControlsCommand({ StandardsSubscriptionArn: arn, NextToken })),
      (r) => r.Controls,
      (r) => r.NextToken,
    );
    const standards = await all(
      (NextToken) => client.send(new DescribeStandardsCommand({ NextToken })),
      (r) => r.Standards,
      (r) => r.NextToken,
    );
    return { sub, controls, standard: standards.find((s) => s.StandardsArn === sub.StandardsArn) };
  });
  if (!data.ok) {
    return (
      <Page title="Standard" back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { sub, controls, standard } = data.value;
  const name = standard?.Name ?? sub.StandardsArn;
  const enabled = controls.filter((c) => c.ControlStatus === "ENABLED").length;
  return (
    <Page
      title={name}
      icon={ICONS.securityhub}
      back={back}
      subtitle={sub.StandardsSubscriptionArn}
      actions={<ActionForm action={disableStandard.bind(null, arn)} submit="Disable standard" icon={<Minus size={16} />} tone="danger" confirm="Disable this standard?" testId="disable-standard" />}
    >
      <Specs
        items={[
          { label: "Status", icon: <ShieldCheck size={15} />, value: <Status tone={sub.StandardsStatus === "READY" ? "good" : "warn"}>{word(sub.StandardsStatus)}</Status> },
          { label: "Enabled controls", icon: <Power size={15} />, value: `${enabled} / ${controls.length}` },
        ]}
      />
      {sub.StandardsStatusReason?.StatusReasonCode && <div className="banner error">{word(sub.StandardsStatusReason.StatusReasonCode)}</div>}
      <List
        label="Controls"
        empty={<Empty icon={ICONS.securityhub} />}
        rows={controls.map((c) => {
          const on = c.ControlStatus === "ENABLED";
          const sev = severity(c.SeverityRating);
          return {
            key: c.StandardsControlArn!,
            icon: <AwsIcon icon={controlIcon(c.ControlId)} size={20} />,
            title: `${c.ControlId} ${c.Title ?? ""}`,
            subtitle: on ? undefined : [c.DisabledReason, c.ControlStatusUpdatedAt ? `since ${when(c.ControlStatusUpdatedAt)}` : ""].filter(Boolean).join(" · "),
            meta: (
              <>
                <Status tone={sev.tone}>{sev.label}</Status>
                {!on && <Pill>{word(c.ControlStatus)}</Pill>}
              </>
            ),
            actions: on ? (
              <Sheet title={`Disable ${c.ControlId}`} label={`Disable ${c.ControlId}`} icon={<PowerOff size={15} />} testId="disable-control">
                <ActionForm action={setControl.bind(null, c.StandardsControlArn!, false)} submit="Disable" tone="danger" testId="disable-control">
                  <Field label="Reason" rule={Rules.DisabledReason}>
                    <input name="reason" required placeholder="Not applicable to this account" />
                  </Field>
                </ActionForm>
              </Sheet>
            ) : (
              <ActionForm action={setControl.bind(null, c.StandardsControlArn!, true)} submit={`Enable ${c.ControlId}`} icon={<Power size={15} />} />
            ),
          };
        })}
      />
    </Page>
  );
}

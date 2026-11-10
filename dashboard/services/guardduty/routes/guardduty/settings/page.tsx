import { GetDetectorCommand } from "@aws-sdk/client-guardduty";
import { load, when } from "@mws-dashboard/aws";
import { ActionForm, Empty, ErrorNotice, Facts, Field, Page, Section, Status, Tags } from "@mws-dashboard/ui";
import { Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, detectorId, guardduty } from "../../../lib/clients";
import { GuardDutyNav } from "../../../lib/nav";
import { deleteDetector, enableGuardDuty, updateDetector } from "../actions";

export const metadata: Metadata = { title: "Settings · GuardDuty" };

const PLANS: [string, string][] = [
  ["S3_DATA_EVENTS", "S3 Protection"],
  ["EKS_AUDIT_LOGS", "EKS Protection"],
  ["RUNTIME_MONITORING", "Runtime Monitoring"],
  ["EBS_MALWARE_PROTECTION", "Malware Protection for EC2"],
  ["RDS_LOGIN_EVENTS", "RDS Protection"],
  ["LAMBDA_NETWORK_LOGS", "Lambda Protection"],
];

export default async function Settings() {
  const data = await load(async () => {
    const detector = await detectorId();
    if (!detector) return undefined;
    return { detector, d: await (await guardduty()).send(new GetDetectorCommand({ DetectorId: detector })) };
  });
  if (!data.ok) {
    return (
      <Page title="Settings">
        <GuardDutyNav active="settings" />
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  if (!data.value) {
    return (
      <Page title="Settings">
        <Empty icon={ICONS.guardduty} action={<ActionForm action={enableGuardDuty} submit="Enable GuardDuty" testId="enable-guardduty" />} />
      </Page>
    );
  }
  const { detector, d } = data.value;
  const on = new Set<string>((d.Features ?? []).filter((f) => f.Status === "ENABLED").map((f) => f.Name!));
  return (
    <Page
      title="Settings"
      actions={<ActionForm action={deleteDetector.bind(null, detector)} submit="Disable GuardDuty" icon={<Trash2 size={16} />} tone="danger" confirm="Disable GuardDuty? This deletes the detector, its findings and its settings." testId="delete-detector" />}
    >
      <GuardDutyNav active="settings" />
      <Facts
        items={[
          ["Detector ID", <code key="id">{detector}</code>],
          ["Status", <Status key="s" tone={d.Status === "ENABLED" ? "good" : "warn"}>{(d.Status ?? "").toLowerCase()}</Status>],
          d.ServiceRole && ["Service role", d.ServiceRole],
          ["Created", when(d.CreatedAt)],
          d.UpdatedAt && ["Updated", when(d.UpdatedAt)],
        ]}
      />
      <Section title="Protection plans and findings export">
        <ActionForm action={updateDetector.bind(null, detector)} submit="Save" testId="detector-settings">
          <fieldset className="checks">
            <legend>Protection plans</legend>
            {PLANS.map(([name, label]) => (
              <label key={name} className="check">
                <input type="checkbox" name="feature" value={name} defaultChecked={on.has(name)} /> {label}
              </label>
            ))}
          </fieldset>
          <Field label="Updated findings published every">
            <select name="frequency" defaultValue={d.FindingPublishingFrequency ?? "SIX_HOURS"}>
              <option value="FIFTEEN_MINUTES">15 minutes</option>
              <option value="ONE_HOUR">1 hour</option>
              <option value="SIX_HOURS">6 hours</option>
            </select>
          </Field>
        </ActionForm>
      </Section>
      <Tags tags={d.Tags} />
    </Page>
  );
}

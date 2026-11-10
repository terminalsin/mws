"use client";

import { ActionForm, Field, Sheet, type Rule } from "@mws-dashboard/ui";
import { CreateAnomalyMonitor, CreateAnomalySubscription } from "@mws-dashboard/ui/model/ce";
import { freeName, PresetGallery } from "@mws-dashboard/ui/presets";
import { Pencil, Tag } from "lucide-react";
import { useState } from "react";

import { createMonitor, createSubscription, renameMonitor, updateSubscription } from "../actions";

const MONITOR_NAME: Rule = { ...CreateAnomalyMonitor.AnomalyMonitor.fields!.MonitorName, maxLength: 1024, generate: { suffix: "-monitor" } };
// AWS shows account IDs as 1234-5678-9012; the API takes the digits.
const ACCOUNTS: Rule = { pattern: "^[0-9]{12}([, ]+[0-9]{12})*$", hint: "12-digit account IDs, comma separated" };
const TAG_KEY: Rule = { ...CreateAnomalyMonitor.ResourceTags.item!.fields!.Key, required: true };
const SUBSCRIPTION = CreateAnomalySubscription.AnomalySubscription.fields!;
const SUBSCRIPTION_NAME: Rule = { ...SUBSCRIPTION.SubscriptionName, generate: { suffix: "-alerts" } };
const ADDRESS = SUBSCRIPTION.Subscribers.item!.fields!.Address;

export interface MonitorChoices {
  /** Monitor names in use. */
  names: string[];
  /** An account can have one AWS services monitor. */
  hasServices: boolean;
  accounts: string[];
  tagKeys: string[];
}

const KINDS = [
  { id: "services", label: "AWS services", icon: "service/AWSCostExplorer", name: "aws-services-monitor", title: "Every service this account uses (one per account)" },
  { id: "accounts", label: "Linked accounts", icon: "service/AWSOrganizations", name: "accounts-monitor", title: "Up to 10 linked accounts" },
  { id: "tag", label: "Cost allocation tag", icon: <Tag size={24} aria-hidden />, name: "tag-monitor", title: "Resources with a tag value" },
];

export function NewMonitor({ names, hasServices, accounts, tagKeys }: MonitorChoices) {
  const [kind, setKind] = useState(KINDS[hasServices ? 1 : 0]);
  return (
    <Sheet title="New monitor" label="Create monitor" testId="create-monitor">
      <ActionForm action={createMonitor} submit="Create" testId="create-monitor">
        <PresetGallery
          label="Watches"
          presets={KINDS.map((k) => (k.id === "services" ? { ...k, added: hasServices, disabled: hasServices } : k))}
          chosen={kind.id}
          choose={(p) => setKind(KINDS.find((k) => k.id === p.id)!)}
        />
        <input type="hidden" name="kind" value={kind.id} />
        <div key={kind.id}>
          <Field label="Name" rule={MONITOR_NAME} taken={names} unique>
            <input name="name" required defaultValue={freeName(kind.name, names)} />
          </Field>
          {kind.id === "accounts" && (
            <Field label="Accounts" rule={ACCOUNTS} known={accounts}>
              <input name="accounts" required placeholder={accounts[0]} defaultValue={accounts.length === 1 ? accounts[0] : undefined} />
            </Field>
          )}
          {kind.id === "tag" && (
            <div className="form-row">
              <Field label="Tag key" rule={TAG_KEY} known={tagKeys}>
                <input name="tagKey" required list="ce-tag-keys" defaultValue={tagKeys.length === 1 ? tagKeys[0] : undefined} />
              </Field>
              <Field label="Values" hint="Comma separated">
                <input name="tagValues" required />
              </Field>
              <datalist id="ce-tag-keys">
                {tagKeys.map((k) => (
                  <option key={k} value={k} />
                ))}
              </datalist>
            </div>
          )}
        </div>
      </ActionForm>
    </Sheet>
  );
}

export interface SubscriptionChoices {
  names: string[];
  monitors: { arn: string; name: string }[];
  topics: string[];
  /** For expanding a bare topic name: `arn:aws:sns:<region>:<account>:{}`. */
  topicArn?: string;
}

export function NewSubscription({ names, monitors, topics, topicArn }: SubscriptionChoices) {
  const [frequency, setFrequency] = useState("DAILY");
  const immediate = frequency === "IMMEDIATE";
  // AWS sends immediate alerts to SNS topics and summaries to email, so
  // the address field checks for what the chosen frequency needs.
  const address: Rule = immediate
    ? { ...ADDRESS, format: "arn", arn: topicArn, known: topics, hint: "An SNS topic ARN" }
    : { ...ADDRESS, format: "email", hint: "An email address" };
  return (
    <Sheet title="New alert subscription" label="Create alert subscription" testId="create-subscription">
      <ActionForm action={createSubscription} submit="Create" testId="create-subscription">
        <Field label="Name" rule={SUBSCRIPTION_NAME} taken={names} unique>
          <input name="name" required defaultValue={freeName("cost-alerts", names)} />
        </Field>
        <Field label="Monitor">
          <select name="monitor" required defaultValue={monitors[0]?.arn}>
            {monitors.map((m) => (
              <option key={m.arn} value={m.arn}>
                {m.name}
              </option>
            ))}
          </select>
        </Field>
        <div className="form-row">
          <Field label="Frequency" rule={SUBSCRIPTION.Frequency}>
            <select name="frequency" value={frequency} onChange={(e) => setFrequency(e.target.value)}>
              <option value="IMMEDIATE">Immediately</option>
              <option value="DAILY">Daily</option>
              <option value="WEEKLY">Weekly</option>
            </select>
          </Field>
          <Field label="Impact over (USD)" rule={{ ...SUBSCRIPTION.Threshold, required: true }}>
            <input name="threshold" type="number" min="0" step="any" defaultValue="100" required />
          </Field>
        </div>
        <Field key={frequency} label={immediate ? "SNS topic" : "Email"} rule={address}>
          <input name="address" required type="text" list={immediate ? "ce-topics" : undefined} autoComplete={immediate ? "off" : "email"} />
        </Field>
        <datalist id="ce-topics">
          {topics.map((t) => (
            <option key={t} value={t} />
          ))}
        </datalist>
      </ActionForm>
    </Sheet>
  );
}

export function RenameMonitor({ arn, name, taken }: { arn: string; name: string; taken: string[] }) {
  return (
    <Sheet title="Rename monitor" label={`Rename ${name}`} icon={<Pencil size={15} />} testId="rename-monitor">
      <ActionForm action={renameMonitor.bind(null, arn)} submit="Save" testId="rename-monitor">
        <Field label="Name" rule={MONITOR_NAME} taken={taken.filter((t) => t !== name)}>
          <input name="name" required defaultValue={name} />
        </Field>
      </ActionForm>
    </Sheet>
  );
}

export interface SubscriptionEdit {
  arn: string;
  name: string;
  frequency: string;
  threshold: number;
  addresses: string[];
  monitorArns: string[];
}

export function EditSubscription({ sub, monitors, topics }: { sub: SubscriptionEdit } & Omit<SubscriptionChoices, "names">) {
  const [frequency, setFrequency] = useState(sub.frequency);
  const immediate = frequency === "IMMEDIATE";
  return (
    <Sheet title="Edit alert subscription" label={`Edit ${sub.name}`} icon={<Pencil size={15} />} testId="edit-subscription">
      <ActionForm action={updateSubscription.bind(null, sub.arn)} submit="Save" testId="edit-subscription">
        <Field label="Name" rule={SUBSCRIPTION_NAME}>
          <input name="name" required defaultValue={sub.name} />
        </Field>
        <fieldset className="checks">
          <legend>Monitors</legend>
          {monitors.map((m) => (
            <label key={m.arn} className="check">
              <input type="checkbox" name="monitor" value={m.arn} defaultChecked={sub.monitorArns.includes(m.arn)} /> {m.name}
            </label>
          ))}
        </fieldset>
        <div className="form-row">
          <Field label="Frequency" rule={SUBSCRIPTION.Frequency}>
            <select name="frequency" value={frequency} onChange={(e) => setFrequency(e.target.value)}>
              <option value="IMMEDIATE">Immediately</option>
              <option value="DAILY">Daily</option>
              <option value="WEEKLY">Weekly</option>
            </select>
          </Field>
          <Field label="Impact over (USD)" rule={{ ...SUBSCRIPTION.Threshold, required: true }}>
            <input name="threshold" type="number" min="0" step="any" defaultValue={sub.threshold} required />
          </Field>
        </div>
        <Field
          key={frequency}
          label={immediate ? "SNS topics" : "Emails"}
          rule={immediate ? { known: topics, hint: "SNS topic ARNs, comma separated" } : { format: "emails", hint: "Comma separated" }}
        >
          <input name="address" required defaultValue={(immediate ? sub.addresses.filter((a) => a.startsWith("arn:")) : sub.addresses.filter((a) => !a.startsWith("arn:"))).join(", ")} />
        </Field>
      </ActionForm>
    </Sheet>
  );
}

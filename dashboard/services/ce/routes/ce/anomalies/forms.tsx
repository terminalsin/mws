"use client";

import { ActionForm, Field, Sheet, type Rule } from "@mws-dashboard/ui";
import { CreateAnomalyMonitor, CreateAnomalySubscription } from "@mws-dashboard/ui/model/ce";
import { useState } from "react";

import { createMonitor, createSubscription } from "../actions";

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

export function NewMonitor({ names, hasServices, accounts, tagKeys }: MonitorChoices) {
  const [kind, setKind] = useState(hasServices ? "accounts" : "services");
  return (
    <Sheet title="New monitor" label="Create monitor" testId="create-monitor">
      <ActionForm action={createMonitor} submit="Create" testId="create-monitor">
        <Field label="Name" rule={MONITOR_NAME} taken={names} unique>
          <input name="name" required autoFocus />
        </Field>
        <Field label="Watches" hint={hasServices ? "This account already watches AWS services" : undefined}>
          <select name="kind" value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="services" disabled={hasServices}>
              AWS services
            </option>
            <option value="accounts">Linked accounts</option>
            <option value="tag">Cost allocation tag</option>
          </select>
        </Field>
        {kind === "accounts" && (
          <Field label="Accounts" rule={ACCOUNTS} known={accounts}>
            <input name="accounts" required placeholder={accounts[0]} />
          </Field>
        )}
        {kind === "tag" && (
          <div className="form-row">
            <Field label="Tag key" rule={TAG_KEY} known={tagKeys}>
              <input name="tagKey" required list="ce-tag-keys" />
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
          <input name="name" required autoFocus />
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

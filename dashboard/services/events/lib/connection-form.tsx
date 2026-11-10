"use client";

// A connection: pick the service it calls (or a plain authorization type),
// which names it and fills the credential fields that service expects.

import type { Rule } from "@mws-dashboard/ui";
import { FieldShell } from "@mws-dashboard/ui/fields";
import { freeName, MoreFields, PresetGallery } from "@mws-dashboard/ui/presets";
import { KeyRound, ShieldCheck, UserRound } from "lucide-react";
import { useState, type ReactNode } from "react";

type Auth = "API_KEY" | "BASIC" | "OAUTH_CLIENT_CREDENTIALS";

interface ConnectionPreset {
  id: string;
  label: string;
  icon: string | ReactNode;
  group?: string;
  auth: Auth;
  name: string;
  keyName?: string;
  title?: string;
}

const PRESETS: ConnectionPreset[] = [
  {
    id: "api-key",
    label: "API key",
    icon: <KeyRound size={26} aria-hidden />,
    auth: "API_KEY",
    name: "api",
    keyName: "x-api-key",
  },
  {
    id: "basic",
    label: "Basic",
    icon: <UserRound size={26} aria-hidden />,
    auth: "BASIC",
    name: "basic-auth",
  },
  {
    id: "oauth",
    label: "OAuth",
    icon: <ShieldCheck size={26} aria-hidden />,
    auth: "OAUTH_CLIENT_CREDENTIALS",
    name: "oauth",
    title: "OAuth client credentials",
  },
  {
    id: "datadog",
    label: "Datadog",
    icon: "brand/datadog",
    group: "Partners",
    auth: "API_KEY",
    name: "datadog",
    keyName: "DD-API-KEY",
  },
  {
    id: "pagerduty",
    label: "PagerDuty",
    icon: "brand/pagerduty",
    group: "Partners",
    auth: "API_KEY",
    name: "pagerduty",
    keyName: "Authorization",
  },
  {
    id: "opsgenie",
    label: "Opsgenie",
    icon: "brand/opsgenie",
    group: "Partners",
    auth: "API_KEY",
    name: "opsgenie",
    keyName: "Authorization",
  },
  {
    id: "github",
    label: "GitHub",
    icon: "brand/github",
    group: "Partners",
    auth: "API_KEY",
    name: "github",
    keyName: "Authorization",
  },
  {
    id: "newrelic",
    label: "New Relic",
    icon: "brand/newrelic",
    group: "Partners",
    auth: "API_KEY",
    name: "newrelic",
    keyName: "Api-Key",
  },
  {
    id: "sentry",
    label: "Sentry",
    icon: "brand/sentry",
    group: "Partners",
    auth: "API_KEY",
    name: "sentry",
    keyName: "Authorization",
  },
  {
    id: "stripe",
    label: "Stripe",
    icon: "brand/stripe",
    group: "Partners",
    auth: "BASIC",
    name: "stripe",
    title: "Stripe: the secret key as the username",
  },
  {
    id: "zendesk",
    label: "Zendesk",
    icon: "brand/zendesk",
    group: "Partners",
    auth: "BASIC",
    name: "zendesk",
  },
  {
    id: "shopify",
    label: "Shopify",
    icon: "brand/shopify",
    group: "Partners",
    auth: "API_KEY",
    name: "shopify",
    keyName: "X-Shopify-Access-Token",
  },
];

export function ConnectionAuthFields({
  rules,
  taken,
  nameRule,
}: {
  rules: Record<"keyName" | "keyValue" | "username" | "password", Rule>;
  taken: string[];
  nameRule: Rule;
}) {
  const [preset, setPreset] = useState(PRESETS[0]);
  const type = preset.auth;
  return (
    <>
      <PresetGallery
        presets={PRESETS}
        chosen={preset.id}
        choose={setPreset}
        label="Connection"
        testId="connection-preset"
      />
      <input type="hidden" name="auth" value={type} />
      <div key={preset.id}>
        <FieldShell
          label="Name"
          rule={nameRule}
          taken={taken}
          unique
          member="Name"
        >
          <input
            name="name"
            required
            defaultValue={freeName(preset.name, taken)}
            spellCheck={false}
          />
        </FieldShell>
        {type === "API_KEY" && (
          <div className="form-row">
            <FieldShell
              label="Header name"
              rule={rules.keyName}
              member="AuthParameters.ApiKeyAuthParameters.ApiKeyName"
            >
              <input
                name="keyName"
                required
                defaultValue={preset.keyName ?? "x-api-key"}
              />
            </FieldShell>
            <FieldShell
              label="Value"
              rule={rules.keyValue}
              member="AuthParameters.ApiKeyAuthParameters.ApiKeyValue"
              generate="token"
            >
              <input
                name="keyValue"
                required
                type="password"
                autoComplete="off"
              />
            </FieldShell>
          </div>
        )}
        {type === "BASIC" && (
          <div className="form-row">
            <FieldShell label="Username" rule={rules.username}>
              <input name="username" required autoComplete="off" />
            </FieldShell>
            <FieldShell
              label="Password"
              rule={rules.password}
              generate="password"
            >
              <input
                name="password"
                required
                type="password"
                autoComplete="new-password"
              />
            </FieldShell>
          </div>
        )}
        {type === "OAUTH_CLIENT_CREDENTIALS" && (
          <>
            <div className="form-row">
              <FieldShell label="Authorization endpoint" format="url">
                <input
                  name="authEndpoint"
                  required
                  placeholder="https://auth.example.com/oauth2/token"
                />
              </FieldShell>
              <FieldShell label="Method">
                <select name="authMethod" defaultValue="POST">
                  <option>POST</option>
                  <option>GET</option>
                  <option>PUT</option>
                </select>
              </FieldShell>
            </div>
            <div className="form-row">
              <FieldShell label="Client ID">
                <input name="clientId" required autoComplete="off" />
              </FieldShell>
              <FieldShell label="Client secret">
                <input
                  name="clientSecret"
                  required
                  type="password"
                  autoComplete="off"
                />
              </FieldShell>
            </div>
          </>
        )}
        <MoreFields>
          <FieldShell label="Description">
            <input name="description" maxLength={512} />
          </FieldShell>
        </MoreFields>
      </div>
    </>
  );
}

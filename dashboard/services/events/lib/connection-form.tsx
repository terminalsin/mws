"use client";

// A connection's credentials follow its authorization type.

import type { Rule } from "@mws-dashboard/ui";
import { FieldShell } from "@mws-dashboard/ui/fields";
import { useState } from "react";

export function ConnectionAuthFields({ rules }: { rules: Record<"keyName" | "keyValue" | "username" | "password", Rule> }) {
  const [type, setType] = useState("API_KEY");
  return (
    <>
      <FieldShell label="Authorization type">
        <select name="auth" value={type} onChange={(e) => setType(e.target.value)}>
          <option value="API_KEY">API key</option>
          <option value="BASIC">Basic</option>
          <option value="OAUTH_CLIENT_CREDENTIALS">OAuth client credentials</option>
        </select>
      </FieldShell>
      {type === "API_KEY" && (
        <div className="form-row">
          <FieldShell label="Header name" rule={rules.keyName} member="AuthParameters.ApiKeyAuthParameters.ApiKeyName">
            <input name="keyName" required defaultValue="x-api-key" />
          </FieldShell>
          <FieldShell label="Value" rule={rules.keyValue} member="AuthParameters.ApiKeyAuthParameters.ApiKeyValue" generate="token">
            <input name="keyValue" required type="password" autoComplete="off" />
          </FieldShell>
        </div>
      )}
      {type === "BASIC" && (
        <div className="form-row">
          <FieldShell label="Username" rule={rules.username}>
            <input name="username" required autoComplete="off" />
          </FieldShell>
          <FieldShell label="Password" rule={rules.password} generate="password">
            <input name="password" required type="password" autoComplete="new-password" />
          </FieldShell>
        </div>
      )}
      {type === "OAUTH_CLIENT_CREDENTIALS" && (
        <>
          <div className="form-row">
            <FieldShell label="Authorization endpoint" format="url">
              <input name="authEndpoint" required placeholder="https://auth.example.com/oauth2/token" />
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
              <input name="clientSecret" required type="password" autoComplete="off" />
            </FieldShell>
          </div>
        </>
      )}
    </>
  );
}

"use client";

// The new-secret fields. The form opens on what the secret is for:
// picking a database fills a name and its connection JSON with a fresh
// password, so the common case is a click and Create. Description, key,
// tags and replication wait under More.

import type { Rule } from "@mws-dashboard/ui";
import { FieldShell } from "@mws-dashboard/ui/fields";
import { CreateSecret } from "@mws-dashboard/ui/model/secretsmanager";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import { KeyRound, Text } from "lucide-react";
import { useEffect, useState } from "react";

import { SECRET_PRESETS, presetValue, type SecretPreset } from "./presets";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

// The model leaves names unconstrained; the characters are in AWS's docs.
const NAME: Rule = { ...CreateSecret.Name, pattern: "^[A-Za-z0-9/_+=.@-]+$", hint: "Letters, digits and /_+=.@-", generate: "name" };
// The console asks for a value; an empty one gets a generated password.
const VALUE: Rule = { ...CreateSecret.SecretString, required: true, format: "jsonish", generate: "password" };
const REGIONS: Rule = { ...CreateSecret.AddReplicaRegions, item: CreateSecret.AddReplicaRegions.item!.fields!.Region };

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_+=!%^*";

/** 32 random characters that survive JSON, URLs and shells. */
function password() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => ALPHABET[b % ALPHABET.length]).join("");
}

const LUCIDE: Record<string, React.ReactNode> = {
  "api-key": <KeyRound size={24} aria-hidden />,
  plaintext: <Text size={24} aria-hidden />,
};

export function SecretFields({ names, keys }: { names: string[]; keys: string[] }) {
  const [preset, setPreset] = useState<SecretPreset>(SECRET_PRESETS[0]);
  // Generated after hydration (and anew per pick), so server and client agree.
  const [secret, setSecret] = useState("");
  useEffect(() => setSecret(password()), [preset]);
  return (
    <>
      <PresetGallery
        label="Secret type"
        presets={SECRET_PRESETS.map((p) => ({ ...p, icon: LUCIDE[p.id] ?? p.icon, added: names.some((n) => n === p.name || n.startsWith(`${p.name}-`)) }))}
        chosen={preset.id}
        choose={(p) => setPreset(SECRET_PRESETS.find((x) => x.id === p.id)!)}
        testId="secret-preset"
      />
      <div key={`${preset.id}:${secret}`} className="preset-fields">
        <FieldShell label="Name" rule={NAME} taken={names} unique>
          <input name="name" placeholder="prod/app/db" defaultValue={freeName(preset.name, names)} />
        </FieldShell>
        <FieldShell label="Value" rule={VALUE} member="SecretString">
          <textarea name="value" rows={preset.value ? Math.min(9, Object.keys(preset.value).length + 2) : 4} className={preset.value ? "code-editor" : undefined} spellCheck={false} defaultValue={secret ? presetValue(preset, secret) : ""} placeholder={preset.value ? undefined : "Any text"} />
        </FieldShell>
        <MoreFields>
          <FieldShell label="Description" rule={CreateSecret.Description}>
            <input name="description" />
          </FieldShell>
          <FieldShell label="KMS key" rule={CreateSecret.KmsKeyId} known={keys}>
            <ResourcePicker kind="kms-key" name="kmsKeyId" placeholder="alias/aws/secretsmanager" />
          </FieldShell>
          <FieldShell label="Tags" format="tags">
            <textarea name="tags" rows={2} placeholder="team=payments" />
          </FieldShell>
          <FieldShell label="Replicate to Regions" rule={REGIONS} member="AddReplicaRegions">
            <input name="regions" placeholder="eu-west-1, ap-southeast-2" />
          </FieldShell>
          <label className="check">
            <input type="checkbox" name="overwrite" /> Overwrite a secret with the same name in those Regions
          </label>
        </MoreFields>
      </div>
    </>
  );
}

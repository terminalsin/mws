import "server-only";

import { DescribeKeyCommand, ListAliasesCommand, ListKeysCommand } from "@aws-sdk/client-kms";
import { collect } from "@mws-dashboard/aws";
import type { Tone } from "@mws-dashboard/ui";

import { kms } from "./clients";

export const STATE_TONE: Record<string, Tone> = { Enabled: "good", Disabled: "neutral", PendingDeletion: "bad", PendingImport: "warn", Unavailable: "bad" };

/** Every alias in the account and Region, AWS managed ones included. */
export async function listAliases() {
  const client = await kms();
  return collect((Marker) => client.send(new ListAliasesCommand({ Marker })), (r) => r.Aliases, (r) => (r.Truncated ? r.NextMarker : undefined));
}

export async function listKeys() {
  const client = await kms();
  const [list, aliases] = await Promise.all([
    collect((Marker) => client.send(new ListKeysCommand({ Marker })), (r) => r.Keys, (r) => (r.Truncated ? r.NextMarker : undefined)),
    listAliases(),
  ]);
  const described = await Promise.all(list.map(async (k) => (await client.send(new DescribeKeyCommand({ KeyId: k.KeyId! }))).KeyMetadata!));
  return described.map((meta) => ({ meta, aliases: aliases.filter((a) => a.TargetKeyId === meta.KeyId).map((a) => a.AliasName!) }));
}

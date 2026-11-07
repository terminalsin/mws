import { DescribeKeyCommand, ListAliasesCommand, ListKeysCommand } from "@aws-sdk/client-kms";
import { collect, load, when } from "@mws-dashboard/aws";
import { ActionForm, Badge, ErrorNotice, Field, PageHeader, Section, Table, type Tone } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { kms } from "../../lib/clients";
import { createKey, scheduleDeletion, setEnabled, tryEncrypt } from "./actions";

export const metadata: Metadata = { title: "KMS keys" };

const STATE_TONE: Record<string, Tone> = { Enabled: "good", Disabled: "neutral", PendingDeletion: "bad", PendingImport: "warn" };

export default async function Keys() {
  const keys = await load(async () => {
    const client = await kms();
    const [list, aliases] = await Promise.all([
      collect(
        (Marker) => client.send(new ListKeysCommand({ Marker })),
        (r) => r.Keys,
        (r) => (r.Truncated ? r.NextMarker : undefined),
      ),
      collect(
        (Marker) => client.send(new ListAliasesCommand({ Marker })),
        (r) => r.Aliases,
        (r) => (r.Truncated ? r.NextMarker : undefined),
      ),
    ]);
    const described = await Promise.all(list.map(async (k) => (await client.send(new DescribeKeyCommand({ KeyId: k.KeyId! }))).KeyMetadata!));
    return described.map((meta) => ({ meta, aliases: aliases.filter((a) => a.TargetKeyId === meta.KeyId).map((a) => a.AliasName!) }));
  });
  const customer = keys.ok ? keys.value.filter((k) => k.meta.KeyManager === "CUSTOMER") : [];
  return (
    <>
      <PageHeader title="KMS keys" description="Keys in the selected region. MWS performs real cryptography with them." />
      <Section title="Create key">
        <ActionForm action={createKey} submit="Create key" inline testId="create-key">
          <Field label="Alias">
            <input name="alias" placeholder="alias/my-key" />
          </Field>
          <Field label="Key spec">
            <select name="spec" defaultValue="SYMMETRIC_DEFAULT">
              {["SYMMETRIC_DEFAULT", "RSA_2048", "RSA_4096", "ECC_NIST_P256", "ECC_SECG_P256K1", "HMAC_256"].map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </Field>
          <Field label="Description">
            <input name="description" />
          </Field>
        </ActionForm>
      </Section>
      <Section title={keys.ok ? `Keys (${keys.value.length})` : "Keys"}>
        {keys.ok ? (
          <Table
            label="Keys"
            rows={keys.value}
            rowKey={(k) => k.meta.KeyId!}
            empty="No keys in this region."
            columns={[
              {
                header: "Key",
                className: "wrap",
                cell: (k) => (
                  <>
                    <div>{k.aliases.join(", ") || <span className="muted">no alias</span>}</div>
                    <code className="muted">{k.meta.KeyId}</code>
                  </>
                ),
              },
              { header: "Spec", cell: (k) => k.meta.KeySpec },
              { header: "Usage", cell: (k) => k.meta.KeyUsage },
              { header: "Manager", cell: (k) => <Badge>{k.meta.KeyManager?.toLowerCase()}</Badge> },
              { header: "State", cell: (k) => <Badge tone={STATE_TONE[k.meta.KeyState ?? ""] ?? "neutral"}>{k.meta.KeyState}</Badge> },
              { header: "Created", cell: (k) => when(k.meta.CreationDate) },
              {
                header: "",
                cell: (k) =>
                  k.meta.KeyManager === "CUSTOMER" &&
                  k.meta.KeyState !== "PendingDeletion" && (
                    <div className="actions-cell">
                      <ActionForm
                        action={setEnabled.bind(null, k.meta.KeyId!, k.meta.KeyState !== "Enabled")}
                        submit={k.meta.KeyState === "Enabled" ? "Disable" : "Enable"}
                        tone={k.meta.KeyState === "Enabled" ? "danger" : "primary"}
                        inline
                      />
                      <ActionForm
                        action={scheduleDeletion.bind(null, k.meta.KeyId!)}
                        submit="Schedule deletion"
                        tone="danger"
                        confirm="Schedule this key for deletion in 7 days?"
                        inline
                      />
                    </div>
                  ),
              },
            ]}
          />
        ) : (
          <ErrorNotice error={keys.error} />
        )}
      </Section>
      {customer.some((k) => k.meta.KeyState === "Enabled" && k.meta.KeyUsage === "ENCRYPT_DECRYPT") && (
        <Section title="Try a key">
          <ActionForm action={tryEncrypt} submit="Encrypt and decrypt" testId="try-key">
            <div className="form-row">
              <Field label="Key">
                <select name="keyId">
                  {customer
                    .filter((k) => k.meta.KeyState === "Enabled" && k.meta.KeyUsage === "ENCRYPT_DECRYPT")
                    .map((k) => (
                      <option key={k.meta.KeyId} value={k.meta.KeyId}>
                        {k.aliases[0] ?? k.meta.KeyId}
                      </option>
                    ))}
                </select>
              </Field>
              <Field label="Plaintext">
                <input name="plaintext" required defaultValue="hello from the MWS console" size={40} />
              </Field>
            </div>
          </ActionForm>
        </Section>
      )}
    </>
  );
}

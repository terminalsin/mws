import {
  DescribeKeyCommand,
  GetKeyLastUsageCommand,
  GetKeyPolicyCommand,
  GetKeyRotationStatusCommand,
  GetPublicKeyCommand,
  ListGrantsCommand,
  ListKeyRotationsCommand,
  ListResourceTagsCommand,
} from "@aws-sdk/client-kms";
import { ago, all, load, when } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { ArrowRightLeft, CalendarX, Crown, Download, Globe, KeyRound, Pencil, Play, Plus, Power, RotateCw, Tag, Trash2, Undo2, Wand2, XCircle } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, kms } from "../../../lib/clients";
import { MOVING, STATE_TONE, USAGE, grantOperations, listAliases, pem } from "../../../lib/kms";
import { ALIAS, CONTEXT, GRANTEE, GRANT_NAME, NEW_DESCRIPTION, PENDING_DAYS, POLICY, RETIRING, ROTATION_DAYS, TAGS, messageRule, takenAliases, tryAlgorithm } from "../../../lib/rules";
import {
  addAlias,
  cancelDeletion,
  createGrant,
  deleteAlias,
  deleteMaterial,
  importMaterial,
  makePrimary,
  moveAlias,
  replicate,
  retireGrant,
  revokeGrant,
  rotateNow,
  saveDescription,
  saveKeyPolicy,
  saveKeyTags,
  saveRotationPeriod,
  scheduleDeletion,
  setEnabled,
  setRotation,
  tryKey,
} from "../actions";

type Props = { searchParams: Promise<{ id?: string; tab?: string }> };

export const metadata: Metadata = { title: "Key" };

const REGIONS = ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-central-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1"];

export default async function Key({ searchParams }: Props) {
  const { id = "", tab: rawTab } = await searchParams;
  const tab = rawTab ?? "policy";
  const back = { href: "/kms", label: "Keys" };
  const data = await load(async () => {
    const client = await kms();
    const meta = (await client.send(new DescribeKeyCommand({ KeyId: id }))).KeyMetadata!;
    const customer = meta.KeyManager === "CUSTOMER";
    const symmetric = meta.KeySpec === "SYMMETRIC_DEFAULT";
    const rotates = symmetric && meta.Origin === "AWS_KMS";
    const [aliasList, policy, rotation, tags, grants, rotations, publicKey, lastUsed] = await Promise.all([
      listAliases(),
      // A policy that can't be read is said so, never shown (or edited) as empty.
      load(() => client.send(new GetKeyPolicyCommand({ KeyId: meta.KeyId, PolicyName: "default" })).then((r) => r.Policy ?? "")),
      rotates ? client.send(new GetKeyRotationStatusCommand({ KeyId: meta.KeyId })).then((r) => r, () => undefined) : undefined,
      customer ? client.send(new ListResourceTagsCommand({ KeyId: meta.KeyId })).then((r) => r.Tags ?? [], () => []) : [],
      load(() => all((Marker) => client.send(new ListGrantsCommand({ KeyId: meta.KeyId, Marker })), (r) => r.Grants, (r) => (r.Truncated ? r.NextMarker : undefined))),
      rotates || meta.Origin === "EXTERNAL"
        ? all((Marker) => client.send(new ListKeyRotationsCommand({ KeyId: meta.KeyId, Marker })), (r) => r.Rotations, (r) => (r.Truncated ? r.NextMarker : undefined)).catch(() => [])
        : [],
      !symmetric && !meta.KeySpec?.startsWith("HMAC") && meta.KeyState === "Enabled"
        ? client.send(new GetPublicKeyCommand({ KeyId: meta.KeyId })).then((r) => r, () => undefined)
        : undefined,
      client.send(new GetKeyLastUsageCommand({ KeyId: meta.KeyId })).then((r) => r, () => undefined),
    ]);
    const aliases = aliasList.filter((a) => a.TargetKeyId === meta.KeyId);
    const otherKeys = aliasList.filter((a) => a.TargetKeyId && a.TargetKeyId !== meta.KeyId && !a.AliasName?.startsWith("alias/aws/"));
    return { meta, customer, rotates, aliases, otherKeys, taken: takenAliases(aliasList.map((a) => a.AliasName!)), policy, rotation, tags, grants, rotations, publicKey, lastUsed };
  });
  if (!data.ok) {
    return (
      <Page title="Key" icon={ICONS.key} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { meta, customer, rotates, aliases, otherKeys, taken, policy, rotation, tags, grants, rotations, publicKey, lastUsed } = data.value;
  const keyId = meta.KeyId!;
  const state = meta.KeyState!;
  const usable = state === "Enabled";
  const usage = meta.KeyUsage!;
  const algorithm = tryAlgorithm(meta);
  const title = aliases[0]?.AliasName?.replace(/^alias\//, "") ?? keyId;
  const base = `/kms/key?id=${encodeURIComponent(keyId)}`;
  const external = meta.Origin === "EXTERNAL";
  const mr = meta.MultiRegionConfiguration;
  const verb = USAGE.find((u) => u.id === usage)?.verb ?? usage;

  const actions = customer && (
    <>
      {state === "PendingDeletion" ? (
        <ActionForm action={cancelDeletion.bind(null, keyId)} submit="Cancel deletion" icon={<Undo2 size={16} />} testId="cancel-deletion" />
      ) : (
        <>
          {(state === "Enabled" || state === "Disabled") && (
            <ActionForm
              action={setEnabled.bind(null, keyId, !usable)}
              submit={usable ? "Disable key" : "Enable key"}
              icon={usable ? <Power size={16} /> : <Play size={16} />}
              testId="toggle-key"
            />
          )}
          <Sheet title="Description" label="Edit description" icon={<Pencil size={16} />} testId="edit-description">
            <ActionForm action={saveDescription.bind(null, keyId)} submit="Save" testId="edit-description">
              <Field label="Description" rule={NEW_DESCRIPTION}>
                <textarea name="description" rows={3} defaultValue={meta.Description} />
              </Field>
            </ActionForm>
          </Sheet>
          <Sheet title="Schedule deletion" label="Schedule deletion" icon={<CalendarX size={16} />} testId="schedule-deletion">
            <ActionForm action={scheduleDeletion.bind(null, keyId)} submit="Schedule" tone="danger" testId="schedule-deletion">
              <Field label="Waiting period (days)" rule={PENDING_DAYS}>
                <input name="days" type="number" min={7} max={30} defaultValue={30} />
              </Field>
            </ActionForm>
          </Sheet>
        </>
      )}
    </>
  );

  const tabs = [
    { id: "policy", label: "Key policy" },
    { id: "crypto", label: "Cryptographic configuration" },
    rotates && { id: "rotation", label: "Key rotation" },
    external && { id: "material", label: "Key material" },
    customer && { id: "aliases", label: "Aliases", count: aliases.length },
    { id: "grants", label: "Grants", count: grants.ok ? grants.value.length : undefined },
    customer && { id: "tags", label: "Tags", count: tags.length || undefined },
    meta.MultiRegion && { id: "regionality", label: "Regionality" },
  ].filter((t): t is { id: string; label: string; count?: number } => !!t);
  // A key waiting for its material opens where it is imported.
  const asked = tab === "policy" && state === "PendingImport" && !rawTab ? "material" : tab;
  const current = tabs.some((t) => t.id === asked) ? asked : "policy";

  let body: React.ReactNode = null;
  if (current === "policy") {
    body = (
      <Section
        title="Key policy"
        actions={
          customer &&
          policy.ok && (
            <Sheet title="Key policy" label="Edit key policy" icon={<Pencil size={16} />} testId="edit-key-policy">
              <ActionForm action={saveKeyPolicy.bind(null, keyId)} submit="Save" testId="edit-key-policy">
                <Field label="Key policy" rule={POLICY}>
                  <textarea name="policy" rows={16} defaultValue={pretty(policy.value)} />
                </Field>
              </ActionForm>
            </Sheet>
          )
        }
      >
        {policy.ok ? <CodeBlock value={policy.value} label="Key policy" /> : <ErrorNotice error={policy.error} />}
      </Section>
    );
  } else if (current === "crypto") {
    const algos = [
      ["Encryption algorithms", meta.EncryptionAlgorithms],
      ["Signing algorithms", meta.SigningAlgorithms],
      ["MAC algorithms", meta.MacAlgorithms],
      ["Key agreement algorithms", meta.KeyAgreementAlgorithms],
      ["Encapsulation algorithms", meta.EncapsulationAlgorithms],
    ] as const;
    body = (
      <>
        <Section title="Cryptographic configuration">
          <Facts
            items={[
              ["Key spec", meta.KeySpec],
              ["Key usage", USAGE.find((u) => u.id === usage)?.title ?? usage],
              ["Origin", meta.Origin],
              meta.CustomKeyStoreId && ["Custom key store", <code key="c">{meta.CustomKeyStoreId}</code>],
              meta.XksKeyConfiguration?.Id && ["External key", <code key="x">{meta.XksKeyConfiguration.Id}</code>],
              ...algos.filter(([, v]) => v?.length).map(([k, v]) => [k, <span key={k} className="chips">{v!.map((a) => <Pill key={a}>{a}</Pill>)}</span>] as [string, React.ReactNode]),
            ]}
          />
        </Section>
        {publicKey?.PublicKey && (
          <Section
            title="Public key"
            actions={
              <a className="icon-button plain" download={`${title}.pem`} href={`data:application/x-pem-file;base64,${Buffer.from(pem(publicKey.PublicKey)).toString("base64")}`} aria-label="Download public key" title="Download">
                <Download size={16} />
              </a>
            }
          >
            <CodeBlock value={pem(publicKey.PublicKey)} label="Public key" />
          </Section>
        )}
      </>
    );
  } else if (current === "rotation" && rotation) {
    body = (
      <>
        <Section
          title="Automatic rotation"
          actions={
            customer && (
              <>
                {usable && <ActionForm action={rotateNow.bind(null, keyId)} submit="Rotate now" icon={<RotateCw size={16} />} confirm="Rotate the key material now?" testId="rotate-now" />}
                <Sheet title="Rotation period" label="Edit rotation period" icon={<Pencil size={16} />} testId="rotation-period">
                  <ActionForm action={saveRotationPeriod.bind(null, keyId)} submit="Save" testId="rotation-period">
                    <Field label="Rotation period (days)" rule={ROTATION_DAYS} member="RotationPeriodInDays">
                      <input name="days" type="number" defaultValue={rotation.RotationPeriodInDays ?? 365} required />
                    </Field>
                  </ActionForm>
                </Sheet>
              </>
            )
          }
        >
          <Facts
            items={[
              [
                "Automatic rotation",
                customer ? (
                  <ActionForm
                    action={setRotation.bind(null, keyId, !rotation.KeyRotationEnabled)}
                    submit={rotation.KeyRotationEnabled ? "Turn rotation off" : "Turn rotation on"}
                    icon={<RotateCw size={15} />}
                    tone={rotation.KeyRotationEnabled ? "primary" : "plain"}
                    testId="toggle-rotation"
                  />
                ) : (
                  "Yearly"
                ),
              ],
              rotation.KeyRotationEnabled && ["Period", `${rotation.RotationPeriodInDays ?? 365} days`],
              rotation.KeyRotationEnabled && rotation.NextRotationDate && ["Next rotation", when(rotation.NextRotationDate)],
              rotation.OnDemandRotationStartDate && ["On-demand rotation", <Status key="o" tone="info">In progress</Status>],
            ]}
          />
          {rotation.OnDemandRotationStartDate && <LiveRefresh />}
        </Section>
        <RotationHistory rotations={rotations} />
      </>
    );
  } else if (current === "material") {
    body = (
      <>
        <Section
          title="Key material"
          actions={
            customer &&
            state !== "PendingDeletion" && (
              <>
                <Sheet title="Import key material" label="Import key material" icon={<KeyRound size={16} />} testId="import-material">
                  <ActionForm action={importMaterial.bind(null, keyId, meta.KeySpec!)} submit="Import" testId="import-material">
                    <Field label="Key material (base64)" hint={meta.KeySpec === "SYMMETRIC_DEFAULT" || meta.KeySpec?.startsWith("HMAC") ? "Empty: generate random material" : undefined}>
                      <textarea name="material" rows={3} className="code-editor" spellCheck={false} />
                    </Field>
                    <Field label="Expires">
                      <input name="validTo" type="datetime-local" />
                    </Field>
                  </ActionForm>
                </Sheet>
                {state !== "PendingImport" && (
                  <ActionForm action={deleteMaterial.bind(null, keyId)} submit="Delete key material" icon={<Trash2 size={16} />} tone="danger" confirm="Delete the imported key material? The key becomes unusable until you import it again." testId="delete-material" />
                )}
              </>
            )
          }
        >
          <Facts
            items={[
              ["State", state === "PendingImport" ? <Status key="s" tone="warn">Pending import</Status> : <Status key="s" tone="good">Imported</Status>],
              meta.ExpirationModel && ["Expiration", meta.ExpirationModel === "KEY_MATERIAL_EXPIRES" ? "Expires" : "Does not expire"],
              meta.ValidTo && ["Expires", when(meta.ValidTo)],
              meta.CurrentKeyMaterialId && ["Current material", <code key="m">{meta.CurrentKeyMaterialId}</code>],
            ]}
          />
        </Section>
        <RotationHistory rotations={rotations} />
      </>
    );
  } else if (current === "aliases") {
    body = (
      <Section
        title="Aliases"
        count={aliases.length}
        plain
        actions={
          <Sheet title="New alias" label="Add alias" icon={<Plus size={16} />} testId="add-alias">
            <ActionForm action={addAlias.bind(null, keyId)} submit="Add" testId="add-alias">
              <Field label="Alias" rule={ALIAS} taken={taken} unique>
                <input name="alias" placeholder="alias/name" required />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        <List
          label="Aliases"
          empty={<Empty>No aliases</Empty>}
          rows={aliases.map((a) => ({
            key: a.AliasName!,
            title: a.AliasName,
            subtitle: a.LastUpdatedDate ? `updated ${ago(a.LastUpdatedDate)}` : undefined,
            actions: (
              <>
                <Sheet title={`Move ${a.AliasName}`} label={`Move ${a.AliasName} to another key`} icon={<ArrowRightLeft size={15} />}>
                  <ActionForm action={moveAlias.bind(null, keyId, a.AliasName!)} submit="Move">
                    <Field label="Key ID or ARN" known={[...new Set(otherKeys.map((k) => k.TargetKeyId!))]} member="TargetKeyId">
                      <input name="target" required />
                    </Field>
                  </ActionForm>
                </Sheet>
                <ActionForm action={deleteAlias.bind(null, keyId, a.AliasName!)} submit={`Remove ${a.AliasName}`} icon={<Trash2 size={15} />} tone="danger" />
              </>
            ),
          }))}
        />
      </Section>
    );
  } else if (current === "grants") {
    const ops = grantOperations(usage, meta.KeySpec === "SYMMETRIC_DEFAULT");
    body = (
      <Section
        title="Grants"
        count={grants.ok ? grants.value.length : undefined}
        plain
        actions={
          customer &&
          state !== "PendingDeletion" && (
            <Sheet title="Create grant" label="Create grant" icon={<Plus size={16} />} testId="create-grant">
              <ActionForm action={createGrant.bind(null, keyId)} submit="Create grant" testId="create-grant">
                <Field label="Grantee principal" rule={GRANTEE} member="GranteePrincipal">
                  <input name="grantee" placeholder="arn:aws:iam::123456789012:role/app" required />
                </Field>
                <fieldset className="checks" aria-label="Operations">
                  <legend>Operations</legend>
                  {ops.map((o) => (
                    <label key={o} className="check">
                      <input type="checkbox" name="operations" value={o} defaultChecked={o === ops[0]} /> {o}
                    </label>
                  ))}
                </fieldset>
                <Field label="Retiring principal" rule={RETIRING} member="RetiringPrincipal">
                  <input name="retiring" />
                </Field>
                <Field label="Name" rule={GRANT_NAME}>
                  <input name="name" />
                </Field>
                {(usage === "ENCRYPT_DECRYPT" && meta.KeySpec === "SYMMETRIC_DEFAULT") && (
                  <div className="form-row">
                    <Field label="Encryption context subset" rule={CONTEXT}>
                      <textarea name="contextSubset" rows={2} placeholder="app=billing" />
                    </Field>
                    <Field label="Encryption context equals" rule={CONTEXT}>
                      <textarea name="contextEquals" rows={2} />
                    </Field>
                  </div>
                )}
              </ActionForm>
            </Sheet>
          )
        }
      >
        {grants.ok ? (
          <List
            label="Grants"
            empty={<Empty>No grants</Empty>}
            rows={grants.value.map((g) => ({
              key: g.GrantId!,
              icon: <KeyRound size={18} aria-hidden />,
              title: g.Name || <code>{g.GrantId?.slice(0, 16)}…</code>,
              subtitle: [
                `to ${g.GranteePrincipal}`,
                g.RetiringPrincipal ? `retired by ${g.RetiringPrincipal}` : null,
                g.Constraints?.EncryptionContextEquals ? `context = ${JSON.stringify(g.Constraints.EncryptionContextEquals)}` : null,
                g.Constraints?.EncryptionContextSubset ? `context ⊇ ${JSON.stringify(g.Constraints.EncryptionContextSubset)}` : null,
              ]
                .filter(Boolean)
                .join(" · "),
              meta: (
                <>
                  {g.Operations?.map((o) => (
                    <Pill key={o}>{o}</Pill>
                  ))}
                  <span>{ago(g.CreationDate)}</span>
                </>
              ),
              actions: customer && (
                <>
                  <ActionForm action={retireGrant.bind(null, keyId, g.GrantId!)} submit={`Retire grant ${g.Name || g.GrantId}`} icon={<XCircle size={15} />} confirm="Retire this grant?" />
                  <ActionForm action={revokeGrant.bind(null, keyId, g.GrantId!)} submit={`Revoke grant ${g.Name || g.GrantId}`} icon={<Trash2 size={15} />} tone="danger" confirm="Revoke this grant?" />
                </>
              ),
            }))}
          />
        ) : (
          <ErrorNotice error={grants.error} />
        )}
      </Section>
    );
  } else if (current === "tags") {
    body = (
      <Section
        title="Tags"
        actions={
          <Sheet title="Tags" label="Edit tags" icon={<Tag size={16} />} testId="edit-tags">
            <ActionForm action={saveKeyTags.bind(null, keyId, tags.map((t) => t.TagKey!))} submit="Save" testId="edit-tags">
              <Field label="Tags" rule={TAGS}>
                <textarea name="tags" rows={6} placeholder="team=payments" defaultValue={tags.map((t) => `${t.TagKey}=${t.TagValue}`).join("\n")} />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {tags.length ? <Tags tags={tags.map((t) => ({ Key: t.TagKey, Value: t.TagValue }))} /> : <Empty>No tags</Empty>}
      </Section>
    );
  } else if (current === "regionality" && mr) {
    const primary = mr.MultiRegionKeyType === "PRIMARY";
    body = (
      <Section
        title="Regionality"
        plain
        actions={
          customer &&
          primary && (
            <Sheet title="Create replica key" label="Create replica key" icon={<Globe size={16} />} testId="replicate-key">
              <ActionForm action={replicate.bind(null, keyId)} submit="Replicate" testId="replicate-key">
                <Field label="Region" known={REGIONS.filter((r) => r !== mr.PrimaryKey?.Region && !mr.ReplicaKeys?.some((k) => k.Region === r))}>
                  <input name="region" required placeholder="eu-west-1" />
                </Field>
                <Field label="Description" rule={NEW_DESCRIPTION}>
                  <input name="description" defaultValue={meta.Description} />
                </Field>
              </ActionForm>
            </Sheet>
          )
        }
      >
        <List
          label="Regions"
          rows={[
            ...(mr.PrimaryKey ? [{ ...mr.PrimaryKey, primary: true }] : []),
            ...(mr.ReplicaKeys ?? []).map((k) => ({ ...k, primary: false })),
          ].map((k) => ({
            key: k.Arn!,
            icon: k.primary ? <Crown size={18} aria-label="Primary" /> : <Globe size={18} aria-label="Replica" />,
            title: k.Region,
            subtitle: k.Arn,
            meta: (
              <>
                {k.primary && <Pill tone="info">primary</Pill>}
                {k.Arn === meta.Arn && <Pill>this key</Pill>}
              </>
            ),
            actions:
              customer && primary && !k.primary && usable ? (
                <ActionForm action={makePrimary.bind(null, meta.Arn!, k.Region!)} submit={`Make ${k.Region} the primary`} icon={<Crown size={15} />} confirm={`Make the replica in ${k.Region} the primary key?`} />
              ) : undefined,
          }))}
        />
      </Section>
    );
  }

  return (
    <Page title={title} icon={ICONS.key} back={back} subtitle={meta.Arn} actions={actions}>
      {MOVING.has(state) && <LiveRefresh />}
      <Specs
        items={[
          { label: "State", icon: <Power size={15} />, value: state === "PendingDeletion" ? <Pill tone="bad">deletes {ago(meta.DeletionDate)}</Pill> : <Status tone={STATE_TONE[state] ?? "neutral"}>{state === "PendingImport" ? "Pending import" : state}</Status> },
          { label: "Usage", icon: <KeyRound size={15} />, value: USAGE.find((u) => u.id === usage)?.title ?? usage },
          meta.KeySpec !== "SYMMETRIC_DEFAULT" && { label: "Spec", icon: <Wand2 size={15} />, value: meta.KeySpec },
          rotation?.KeyRotationEnabled && { label: "Rotation", icon: <RotateCw size={15} />, value: `every ${rotation.RotationPeriodInDays ?? 365} days` },
          meta.MultiRegion && { label: "Multi-Region", icon: <Globe size={15} />, value: mr?.MultiRegionKeyType === "REPLICA" ? `replica of ${mr.PrimaryKey?.Region}` : `primary · ${mr?.ReplicaKeys?.length ?? 0} replicas` },
          meta.Origin !== "AWS_KMS" && { label: "Origin", icon: <Download size={15} />, value: meta.Origin === "EXTERNAL" ? "Imported" : meta.Origin },
          meta.ValidTo && { label: "Material expires", icon: <CalendarX size={15} />, value: when(meta.ValidTo) },
          { label: "Created", icon: <Plus size={15} />, value: ago(meta.CreationDate) },
          lastUsed?.KeyLastUsage?.Timestamp && { label: "Last used", icon: <Play size={15} />, value: `${lastUsed.KeyLastUsage.Operation} ${ago(lastUsed.KeyLastUsage.Timestamp)}` },
        ]}
      />
      {meta.Description && <p className="muted">{meta.Description}</p>}

      {usable && (
        <Section title={verb} icon={<Wand2 size={16} />}>
          <ActionForm action={tryKey.bind(null, keyId, usage, meta.KeySpec!, algorithm)} submit="Run" inline testId="try-key">
            {usage === "ENCAPSULATE_DECAPSULATE" ? null : usage === "KEY_AGREEMENT" ? (
              <Field label="Peer public key" hint="Empty: an ephemeral peer, checked against its own ECDH">
                <textarea name="plaintext" rows={2} placeholder="-----BEGIN PUBLIC KEY-----" className="code-editor" spellCheck={false} />
              </Field>
            ) : (
              <Field label={usage === "ENCRYPT_DECRYPT" ? "Plaintext" : "Message"} rule={messageRule(usage, meta.KeySpec!, algorithm)}>
                <input name="plaintext" placeholder="hello" required />
              </Field>
            )}
          </ActionForm>
        </Section>
      )}

      <Segments label="Key" items={tabs.map((t) => ({ label: t.label, href: t.id === "policy" ? base : `${base}&tab=${t.id}`, active: t.id === current, count: t.count }))} />
      {body}
    </Page>
  );
}

function RotationHistory({ rotations }: { rotations: { KeyMaterialId?: string; RotationDate?: Date; RotationType?: string; KeyMaterialState?: string; ImportState?: string }[] }) {
  if (!rotations.length) return null;
  return (
    <Section title="Rotation history" count={rotations.length} plain>
      <List
        label="Rotations"
        rows={[...rotations].reverse().map((r, i) => ({
          key: r.KeyMaterialId ?? String(i),
          icon: <RotateCw size={16} aria-hidden />,
          title: r.RotationDate ? when(r.RotationDate) : <code>{r.KeyMaterialId}</code>,
          subtitle: r.KeyMaterialId,
          meta: (
            <>
              {r.RotationType && <Pill>{r.RotationType.toLowerCase().replace("_", " ")}</Pill>}
              {r.KeyMaterialState === "CURRENT" && <Pill tone="good">current</Pill>}
              {r.ImportState === "PENDING_IMPORT" && <Pill tone="warn">pending import</Pill>}
            </>
          ),
        }))}
      />
    </Section>
  );
}

function pretty(doc: string | undefined) {
  try {
    return JSON.stringify(JSON.parse(doc ?? ""), null, 2);
  } catch {
    return doc ?? "";
  }
}


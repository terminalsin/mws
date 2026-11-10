import { DescribeSecretCommand, GetResourcePolicyCommand, GetSecretValueCommand, ListSecretVersionIdsCommand } from "@aws-sdk/client-secrets-manager";
import { ago, all, load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Status, Tags, type Rule } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { MoreFields } from "@mws-dashboard/ui/presets";
import { DeleteSecret, PutResourcePolicy, PutSecretValue, ReplicateSecretToRegions, RotateSecret, UpdateSecret, UpdateSecretVersionStage } from "@mws-dashboard/ui/model/secretsmanager";
import { ArrowUpFromLine, BadgeCheck, CircleSlash, Eye, EyeOff, Globe, Pencil, Plus, RotateCw, Settings2, ShieldCheck, Tag, Trash2, Undo2, X } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, secrets } from "../../../lib/clients";
import { functionArns, kmsKeys } from "../../../lib/known";
import { secretLogo } from "../../../lib/presets";
import {
  addReplicas,
  addStage,
  cancelRotation,
  deletePolicy,
  deleteSecret,
  moveStage,
  promote,
  putValue,
  removeReplica,
  removeStage,
  restore,
  rotate,
  rotateNow,
  savePolicy,
  saveTags,
  updateSecret,
  validatePolicy,
} from "../actions";

type Props = { searchParams: Promise<{ id?: string; reveal?: string; tab?: string; version?: string }> };

export const metadata: Metadata = { title: "Secret" };

const VALUE: Rule = { ...PutSecretValue.SecretString, format: "jsonish", generate: "password" };
const RULES = RotateSecret.RotationRules.fields!;
const DAYS: Rule = RULES.AutomaticallyAfterDays;
const EXPRESSION: Rule = { ...RULES.ScheduleExpression, hint: "rate(4 hours) or cron(0 16 1,15 * ? *)" };
const DURATION: Rule = { ...RULES.Duration, hint: "Window, like 3h" };
// AWS's documented recovery window; the model has no range.
const WINDOW: Rule = { ...DeleteSecret.RecoveryWindowInDays, min: 7, max: 30, default: 30 };
const REGIONS: Rule = { ...ReplicateSecretToRegions.AddReplicaRegions, item: ReplicateSecretToRegions.AddReplicaRegions.item!.fields!.Region };
const POLICY: Rule = { ...PutResourcePolicy.ResourcePolicy, format: "policy" };
const STAGE: Rule = UpdateSecretVersionStage.VersionStage;
const KNOWN_REGIONS = ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-central-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1"];
const REPLICA_TONE = { InSync: "good", InProgress: "info", Failed: "bad" } as const;

/** "every 30 days", "rate(4 hours)", "cron(...)", with the window when set. */
function schedule(rules: { AutomaticallyAfterDays?: number; ScheduleExpression?: string; Duration?: string } | undefined) {
  if (!rules) return undefined;
  const what = rules.ScheduleExpression ?? (rules.AutomaticallyAfterDays ? `every ${rules.AutomaticallyAfterDays} days` : undefined);
  return [what, rules.Duration ? `within ${rules.Duration}` : null].filter(Boolean).join(", ");
}

export default async function Secret({ searchParams }: Props) {
  const { id = "", reveal, tab = "overview", version } = await searchParams;
  const back = { href: "/secrets", label: "Secrets" };
  const client = await secrets();
  const meta = await load(() => client.send(new DescribeSecretCommand({ SecretId: id })));
  if (!meta.ok) {
    return (
      <Page title="Secret" icon={ICONS.secrets} back={back}>
        <ErrorNotice error={meta.error} />
      </Page>
    );
  }
  const s = meta.value;
  const deleted = !!s.DeletedDate;
  // A replica is read-only: only its primary changes it.
  const replica = !!s.PrimaryRegion && s.ARN?.split(":")[3] !== s.PrimaryRegion;
  const writable = !deleted && !replica;
  const self = `/secrets/secret?id=${encodeURIComponent(id)}`;
  const stages = Object.entries(s.VersionIdsToStages ?? {});
  const current = stages.find(([, st]) => st?.includes("AWSCURRENT"))?.[0];
  const rotating = stages.some(([, st]) => st?.includes("AWSPENDING"));
  const [functions, keys] = writable ? await Promise.all([functionArns(), kmsKeys()]) : [[], []];
  // A bare function name expands to an ARN in the secret's account and Region.
  const [, , , secretRegion, account] = (s.ARN ?? "").split(":");
  const lambdaArn = `arn:aws:lambda:${secretRegion}:${account}:function:{}`;
  const fn = s.RotationLambdaARN?.split(":function:")[1]?.split(":")[0];
  const replicas = s.ReplicationStatus ?? [];
  const tagKeys = (s.Tags ?? []).map((t) => t.Key!);

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "rotation", label: "Rotation" },
    { id: "versions", label: "Versions", count: stages.length },
    { id: "replication", label: "Replication", count: replicas.length || undefined },
    { id: "permissions", label: "Resource permissions" },
    { id: "tags", label: "Tags", count: s.Tags?.length || undefined },
  ];
  const active = tabs.some((t) => t.id === tab) ? tab : "overview";

  const rotationSheet = (
    <Sheet title="Rotation" label={s.RotationEnabled ? "Edit rotation" : "Configure rotation"} icon={<Settings2 size={16} />} testId="rotate-secret">
      <ActionForm action={rotate.bind(null, id)} submit="Save" testId="rotate-secret">
        <Field label="Rotation function" rule={RotateSecret.RotationLambdaARN} format="arn" arn={lambdaArn} known={functions} member="RotationLambdaARN">
          {/* Without a function already set, rotation needs one. */}
          <input name="lambda" defaultValue={s.RotationLambdaARN} required={!s.RotationLambdaARN} placeholder="arn:aws:lambda:…" />
        </Field>
        <div className="form-row">
          <Field label="Every (days)" rule={DAYS} member="RotationRules.AutomaticallyAfterDays">
            <input name="days" type="number" defaultValue={s.RotationRules?.ScheduleExpression ? undefined : s.RotationRules?.AutomaticallyAfterDays} placeholder="30" />
          </Field>
          <Field label="Or schedule expression" rule={EXPRESSION} member="RotationRules.ScheduleExpression">
            <input name="expression" defaultValue={s.RotationRules?.ScheduleExpression} placeholder="rate(30 days)" />
          </Field>
        </div>
        <MoreFields expanded={!!s.RotationRules?.Duration}>
          <Field label="Window duration" rule={DURATION} member="RotationRules.Duration">
            <input name="duration" defaultValue={s.RotationRules?.Duration} placeholder="3h" />
          </Field>
        </MoreFields>
        <label className="check">
          <input type="checkbox" name="immediately" defaultChecked={!s.RotationEnabled} /> Rotate immediately
        </label>
      </ActionForm>
    </Sheet>
  );

  const actions = deleted ? (
    <ActionForm action={restore.bind(null, id)} submit="Restore secret" icon={<Undo2 size={16} />} testId="restore-secret" />
  ) : replica ? (
    <ActionForm action={promote.bind(null, id)} submit="Promote to standalone secret" icon={<ArrowUpFromLine size={16} />} confirm="Promote this replica to a standalone secret? It stops replicating." testId="promote-replica" />
  ) : (
    <>
      <Sheet title="Edit secret" label="Edit description and key" icon={<Pencil size={16} />} testId="edit-secret">
        <ActionForm action={updateSecret.bind(null, id)} submit="Save" testId="edit-secret">
          <Field label="Description" rule={UpdateSecret.Description}>
            <input name="description" defaultValue={s.Description} />
          </Field>
          <Field label="KMS key" rule={UpdateSecret.KmsKeyId} known={keys} hint="Empty keeps the current key">
            <input name="kmsKeyId" defaultValue={s.KmsKeyId} placeholder="alias/aws/secretsmanager" />
          </Field>
        </ActionForm>
      </Sheet>
      <Sheet title="New value" label="Store a new value" icon={<Plus size={16} />} testId="put-secret-value">
        <ActionForm action={putValue.bind(null, id)} submit="Store" testId="put-secret-value">
          <Field label="Value" rule={VALUE} member="SecretString">
            <textarea name="value" rows={8} required />
          </Field>
        </ActionForm>
      </Sheet>
      {rotationSheet}
      <Sheet title="Delete secret" label="Delete secret" icon={<Trash2 size={16} />} testId="delete-secret">
        <ActionForm action={deleteSecret.bind(null, id)} submit="Delete" tone="danger" testId="delete-secret">
          <Field label="Recovery window (days)" rule={WINDOW} member="RecoveryWindowInDays">
            <input name="days" type="number" defaultValue={30} />
          </Field>
          <label className="check">
            <input type="checkbox" name="force" /> Delete now, without recovery
          </label>
        </ActionForm>
      </Sheet>
    </>
  );

  let body: React.ReactNode = null;
  if (active === "overview") {
    const value = reveal && !deleted ? await load(() => client.send(new GetSecretValueCommand({ SecretId: id }))) : null;
    body = !deleted && (
      <Section
        title="Value"
        actions={
          <Link className="icon-button plain" href={reveal ? self : `${self}&reveal=1`} aria-label={reveal ? "Hide value" : "Reveal value"} title={reveal ? "Hide" : "Reveal"}>
            {reveal ? <EyeOff size={16} /> : <Eye size={16} />}
          </Link>
        }
      >
        {value ? (
          value.ok ? (
            <CodeBlock value={value.value.SecretString ?? (value.value.SecretBinary ? Buffer.from(value.value.SecretBinary).toString("base64") : "")} label="Secret value" />
          ) : (
            <ErrorNotice error={value.error} />
          )
        ) : (
          <span className="muted" aria-label="Hidden">••••••••••••</span>
        )}
      </Section>
    );
  } else if (active === "rotation") {
    body = (
      <Section
        title="Rotation configuration"
        actions={
          writable && (
            <>
              {s.RotationEnabled && <ActionForm action={rotateNow.bind(null, id)} submit="Rotate secret immediately" icon={<RotateCw size={16} />} confirm="Rotate the secret now?" testId="rotate-now" />}
              {s.RotationEnabled && <ActionForm action={cancelRotation.bind(null, id)} submit="Turn off rotation" icon={<CircleSlash size={16} />} tone="danger" confirm="Turn off automatic rotation?" testId="cancel-rotation" />}
            </>
          )
        }
      >
        <Facts
          items={[
            ["Rotation", s.RotationEnabled ? <Status key="r" tone="good">Enabled</Status> : <Status key="r" tone="neutral">Disabled</Status>],
            rotating && ["In progress", <Status key="p" tone="info">Rotating</Status>],
            schedule(s.RotationRules) && ["Schedule", schedule(s.RotationRules)],
            s.RotationLambdaARN && [
              "Rotation function",
              fn ? (
                <Link key="f" href={`/lambda/${encodeURIComponent(fn)}`}>
                  {fn}
                </Link>
              ) : (
                s.RotationLambdaARN
              ),
            ],
            s.LastRotatedDate && ["Last rotated", when(s.LastRotatedDate)],
            s.NextRotationDate && ["Next rotation", when(s.NextRotationDate)],
          ]}
        />
      </Section>
    );
  } else if (active === "versions") {
    const versions = await load(() =>
      all((NextToken) => client.send(new ListSecretVersionIdsCommand({ SecretId: id, IncludeDeprecated: true, NextToken })), (r) => r.Versions, (r) => r.NextToken),
    );
    const shown = version ? await load(() => client.send(new GetSecretValueCommand({ SecretId: id, VersionId: version }))) : null;
    const holders = Object.fromEntries(stages.flatMap(([v, st]) => (st ?? []).map((x) => [x, v])));
    body = (
      <>
        {shown && (
          <Section title={<code>{version}</code>} actions={<Link className="icon-button plain" href={`${self}&tab=versions`} aria-label="Hide value" title="Hide"><X size={16} /></Link>}>
            {shown.ok ? (
              <CodeBlock value={shown.value.SecretString ?? (shown.value.SecretBinary ? Buffer.from(shown.value.SecretBinary).toString("base64") : "")} label="Version value" />
            ) : (
              <ErrorNotice error={shown.error} />
            )}
          </Section>
        )}
        <Section title="Versions" plain count={versions.ok ? versions.value.length : undefined}>
          {versions.ok ? (
            <List
              label="Versions"
              rows={[...versions.value]
                .sort((a, b) => (b.CreatedDate?.getTime() ?? 0) - (a.CreatedDate?.getTime() ?? 0))
                .map((v) => {
                  const st = v.VersionStages ?? [];
                  return {
                    key: v.VersionId!,
                    icon: <AwsIcon icon={ICONS.secrets} size={20} />,
                    title: <code>{v.VersionId}</code>,
                    subtitle: [v.CreatedDate ? `created ${ago(v.CreatedDate)}` : null, v.LastAccessedDate ? `read ${ago(v.LastAccessedDate)}` : null, st.length ? null : "deprecated"].filter(Boolean).join(" · "),
                    meta: st.map((x) => (
                      <Pill key={x} tone={x === "AWSCURRENT" ? "good" : x === "AWSPENDING" ? "info" : "neutral"}>
                        {x}
                      </Pill>
                    )),
                    actions: (
                      <>
                        {!deleted && (
                          <Link className="icon-button plain" href={`${self}&tab=versions&version=${encodeURIComponent(v.VersionId!)}`} aria-label={`View ${v.VersionId}`} title="View value">
                            <Eye size={15} />
                          </Link>
                        )}
                        {writable && !st.includes("AWSCURRENT") && current && (
                          <ActionForm
                            action={moveStage.bind(null, id, "AWSCURRENT", v.VersionId!, current)}
                            submit={`Make ${v.VersionId} current`}
                            icon={<BadgeCheck size={15} />}
                            confirm="Move AWSCURRENT to this version? Applications reading the secret get this value."
                          />
                        )}
                        {writable && (
                          <Sheet title="Add staging label" label={`Label ${v.VersionId}`} icon={<Tag size={15} />}>
                            <ActionForm action={addStage.bind(null, id, v.VersionId!, holders)} submit="Add label">
                              <Field label="Label" rule={STAGE} known={Object.keys(holders)}>
                                <input name="stage" required placeholder="v2-release" />
                              </Field>
                            </ActionForm>
                          </Sheet>
                        )}
                        {writable &&
                          st
                            .filter((x) => x !== "AWSCURRENT")
                            .map((x) => (
                              <ActionForm key={x} action={removeStage.bind(null, id, x, v.VersionId!)} submit={`Remove ${x} from ${v.VersionId}`} icon={<X size={15} />} tone="danger" />
                            ))}
                      </>
                    ),
                  };
                })}
            />
          ) : (
            <ErrorNotice error={versions.error} />
          )}
        </Section>
      </>
    );
  } else if (active === "replication") {
    body = (
      <Section
        title="Replicate secret"
        plain
        actions={
          writable && (
            <Sheet title="Add replica Regions" label="Add Regions" icon={<Globe size={16} />} testId="add-replicas">
              <ActionForm action={addReplicas.bind(null, id)} submit="Replicate" testId="add-replicas">
                <Field label="Regions" rule={REGIONS} known={KNOWN_REGIONS.filter((r) => r !== secretRegion && !replicas.some((x) => x.Region === r))} member="AddReplicaRegions">
                  <input name="regions" required placeholder="eu-west-1, ap-southeast-2" />
                </Field>
                <Field label="KMS key in those Regions" hint="Empty: aws/secretsmanager">
                  <input name="kmsKeyId" />
                </Field>
                <label className="check">
                  <input type="checkbox" name="overwrite" /> Overwrite a secret with the same name there
                </label>
              </ActionForm>
            </Sheet>
          )
        }
      >
        {replica && (
          <Facts items={[["Primary Region", s.PrimaryRegion]]} />
        )}
        {replicas.some((r) => r.Status === "InProgress") && <LiveRefresh />}
        <List
          label="Replicas"
          empty={!replica ? <Empty>Not replicated</Empty> : undefined}
          rows={replicas.map((r) => ({
            key: r.Region!,
            icon: <Globe size={18} aria-hidden />,
            title: r.Region,
            subtitle: [r.StatusMessage, r.KmsKeyId && r.KmsKeyId !== "alias/aws/secretsmanager" ? `key ${r.KmsKeyId}` : null, r.LastAccessedDate ? `read ${ago(r.LastAccessedDate)}` : null].filter(Boolean).join(" · "),
            meta: <Status tone={REPLICA_TONE[r.Status as keyof typeof REPLICA_TONE] ?? "neutral"}>{r.Status === "InProgress" ? "Replicating" : r.Status}</Status>,
            actions: writable && <ActionForm action={removeReplica.bind(null, id, r.Region!)} submit={`Remove replica in ${r.Region}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete the replica in ${r.Region}?`} />,
          }))}
        />
      </Section>
    );
  } else if (active === "permissions") {
    const policy = await load(() => client.send(new GetResourcePolicyCommand({ SecretId: id })).then((r) => r.ResourcePolicy));
    body = (
      <Section
        title="Resource permissions"
        icon={<ShieldCheck size={16} />}
        actions={
          writable &&
          policy.ok && (
            <>
              <Sheet title="Resource policy" label="Edit permissions" icon={<Pencil size={16} />} testId="edit-policy">
                <ActionForm action={savePolicy.bind(null, id)} submit="Save" testId="edit-policy">
                  <Field label="Policy" rule={POLICY} member="ResourcePolicy">
                    <textarea name="policy" rows={14} className="code-editor" spellCheck={false} defaultValue={pretty(policy.value) || template(account)} />
                  </Field>
                  <label className="check">
                    <input type="checkbox" name="block" defaultChecked /> Block public access
                  </label>
                </ActionForm>
                <ActionForm action={validatePolicy.bind(null, id)} submit="Validate" testId="validate-policy">
                  <Field label="Policy to validate" rule={POLICY} member="ResourcePolicy">
                    <textarea name="policy" rows={6} className="code-editor" spellCheck={false} defaultValue={pretty(policy.value) || template(account)} />
                  </Field>
                </ActionForm>
              </Sheet>
              {policy.value && <ActionForm action={deletePolicy.bind(null, id)} submit="Delete resource policy" icon={<Trash2 size={16} />} tone="danger" confirm="Delete the resource policy?" testId="delete-policy" />}
            </>
          )
        }
      >
        {policy.ok ? policy.value ? <CodeBlock value={policy.value} label="Resource policy" /> : <Empty>No resource policy</Empty> : <ErrorNotice error={policy.error} />}
      </Section>
    );
  } else if (active === "tags") {
    body = (
      <Section
        title="Tags"
        actions={
          writable && (
            <Sheet title="Tags" label="Edit tags" icon={<Tag size={16} />} testId="edit-tags">
              <ActionForm action={saveTags.bind(null, id, tagKeys)} submit="Save" testId="edit-tags">
                <Field label="Tags" format="tags">
                  <textarea name="tags" rows={6} placeholder="team=payments" defaultValue={(s.Tags ?? []).map((t) => `${t.Key}=${t.Value ?? ""}`).join("\n")} />
                </Field>
              </ActionForm>
            </Sheet>
          )
        }
      >
        {s.Tags?.length ? <Tags tags={s.Tags} /> : <Empty>No tags</Empty>}
      </Section>
    );
  }

  return (
    <Page title={s.Name} icon={secretLogo(s.Name ?? "") ?? ICONS.secrets} back={back} subtitle={s.ARN} actions={actions}>
      {rotating && <LiveRefresh />}
      <Facts
        items={[
          deleted && ["Deletes", <Pill key="d" tone="bad">{ago(s.DeletedDate)}</Pill>],
          replica && ["Replica of", `${s.PrimaryRegion}`],
          s.Description && ["Description", s.Description],
          ["KMS key", s.KmsKeyId ? <Link key="k" href={`/kms/key?id=${encodeURIComponent(s.KmsKeyId)}`}>{s.KmsKeyId.split("/").pop()}</Link> : <Link key="k" href="/kms?tab=aws">aws/secretsmanager</Link>],
          s.RotationEnabled && ["Rotation", schedule(s.RotationRules) ?? "on"],
          s.RotationEnabled && fn && ["Rotation function", <Link key="f" href={`/lambda/${encodeURIComponent(fn)}`}>{fn}</Link>],
          rotating && ["Rotating", <Status key="p" tone="info">Rotating</Status>],
          s.LastRotatedDate && ["Rotated", ago(s.LastRotatedDate)],
          s.NextRotationDate && ["Next rotation", ago(s.NextRotationDate)],
          ["Changed", ago(s.LastChangedDate ?? s.CreatedDate)],
          s.LastAccessedDate && ["Read", ago(s.LastAccessedDate)],
          s.OwningService && ["Managed by", s.OwningService],
          s.Type && ["Type", s.Type],
        ]}
      />
      <Segments label="Secret" items={tabs.map((t) => ({ label: t.label, href: t.id === "overview" ? self : `${self}&tab=${t.id}`, active: t.id === active, count: t.count }))} />
      {body}
    </Page>
  );
}

/** A starting point: this account may read the secret. */
function template(account: string) {
  return JSON.stringify(
    { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: `arn:aws:iam::${account}:root` }, Action: "secretsmanager:GetSecretValue", Resource: "*" }] },
    null,
    2,
  );
}

function pretty(doc: string | undefined) {
  if (!doc) return "";
  try {
    return JSON.stringify(JSON.parse(doc), null, 2);
  } catch {
    return doc;
  }
}

import { DescribeSecretCommand, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, ErrorNotice, Facts, Field, List, Page, Pill, Section, Sheet, Tags, type Rule } from "@mws-dashboard/ui";
import { DeleteSecret, PutSecretValue, RotateSecret } from "@mws-dashboard/ui/model/secretsmanager";
import { Eye, EyeOff, Pencil, RotateCw, Trash2, Undo2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, secrets } from "../../../lib/clients";
import { functionArns } from "../../../lib/known";
import { deleteSecret, putValue, restore, rotate } from "../actions";

type Props = { searchParams: Promise<{ id?: string; reveal?: string }> };

export const metadata: Metadata = { title: "Secret" };

const VALUE: Rule = { ...PutSecretValue.SecretString, format: "jsonish", generate: "password" };
const DAYS: Rule = RotateSecret.RotationRules.fields!.AutomaticallyAfterDays;
// AWS's documented recovery window; the model has no range.
const WINDOW: Rule = { ...DeleteSecret.RecoveryWindowInDays, min: 7, max: 30, default: 30 };

export default async function Secret({ searchParams }: Props) {
  const { id = "", reveal } = await searchParams;
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
  const value = reveal && !deleted ? await load(() => client.send(new GetSecretValueCommand({ SecretId: id }))) : null;
  const self = `/secrets/secret?id=${encodeURIComponent(id)}`;
  const versions = Object.entries(s.VersionIdsToStages ?? {});
  const functions = deleted ? [] : await functionArns();
  // A bare function name expands to an ARN in the secret's account and Region.
  const [, , , secretRegion, account] = (s.ARN ?? "").split(":");
  const lambdaArn = `arn:aws:lambda:${secretRegion}:${account}:function:{}`;

  return (
    <Page
      title={s.Name}
      icon={ICONS.secrets}
      back={back}
      subtitle={s.ARN}
      actions={
        deleted ? (
          <ActionForm action={restore.bind(null, id)} submit="Restore secret" icon={<Undo2 size={16} />} testId="restore-secret" />
        ) : (
          <>
            <Sheet title="New value" label="Store a new value" icon={<Pencil size={16} />} testId="put-secret-value">
              <ActionForm action={putValue.bind(null, id)} submit="Store" testId="put-secret-value">
                <Field label="Value" rule={VALUE} member="SecretString">
                  <textarea name="value" rows={8} required />
                </Field>
              </ActionForm>
            </Sheet>
            <Sheet title="Rotate" label="Rotate" icon={<RotateCw size={16} />} testId="rotate-secret">
              <ActionForm action={rotate.bind(null, id)} submit="Rotate now" testId="rotate-secret">
                <Field label="Rotation function" rule={RotateSecret.RotationLambdaARN} format="arn" arn={lambdaArn} known={functions} member="RotationLambdaARN">
                  {/* Without a function already set, rotation needs one. */}
                  <input name="lambda" defaultValue={s.RotationLambdaARN} required={!s.RotationLambdaARN} placeholder="arn:aws:lambda:…" />
                </Field>
                <Field label="Every (days)" rule={DAYS} member="RotationRules.AutomaticallyAfterDays">
                  <input name="days" type="number" defaultValue={s.RotationRules?.AutomaticallyAfterDays} />
                </Field>
              </ActionForm>
            </Sheet>
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
        )
      }
    >
      <Facts
        items={[
          deleted && ["Deletes", <Pill key="d" tone="bad">{ago(s.DeletedDate)}</Pill>],
          s.Description && ["Description", s.Description],
          s.KmsKeyId && ["KMS key", <Link key="k" href={`/kms/key?id=${encodeURIComponent(s.KmsKeyId)}`}>{s.KmsKeyId.split("/").pop()}</Link>],
          s.RotationEnabled && ["Rotation", `every ${s.RotationRules?.AutomaticallyAfterDays ?? "?"} days`],
          s.NextRotationDate && ["Next rotation", ago(s.NextRotationDate)],
          ["Changed", ago(s.LastChangedDate ?? s.CreatedDate)],
          s.LastAccessedDate && ["Read", ago(s.LastAccessedDate)],
          s.ReplicationStatus?.length && ["Replicas", s.ReplicationStatus.map((r) => r.Region).join(", ")],
          s.Tags?.length && ["Tags", <Tags key="t" tags={s.Tags} />],
        ]}
      />
      {!deleted && (
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
      )}
      {versions.length > 1 && (
        <Section title="Versions" count={versions.length} plain>
          <List
            label="Versions"
            rows={versions.map(([v, stages]) => ({
              key: v,
              icon: <AwsIcon icon={ICONS.secrets} size={20} />,
              title: <code>{v}</code>,
              meta: stages?.map((st) => (
                <Pill key={st} tone={st === "AWSCURRENT" ? "good" : "neutral"}>
                  {st.replace(/^AWS/, "").toLowerCase()}
                </Pill>
              )),
            }))}
          />
        </Section>
      )}
    </Page>
  );
}

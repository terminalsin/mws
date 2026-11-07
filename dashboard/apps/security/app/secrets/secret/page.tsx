import { DescribeSecretCommand, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { load, when } from "@mws-dashboard/aws";
import { ActionForm, Badge, CodeBlock, ErrorNotice, Field, KeyValue, PageHeader, Section } from "@mws-dashboard/ui";
import type { Metadata } from "next";
import Link from "next/link";

import { secrets } from "../../../lib/clients";
import { deleteSecret, putValue } from "../actions";

type Props = { searchParams: Promise<{ id?: string; reveal?: string }> };

export const metadata: Metadata = { title: "Secret" };

export default async function Secret({ searchParams }: Props) {
  const { id = "", reveal } = await searchParams;
  const client = await secrets();
  const meta = await load(() => client.send(new DescribeSecretCommand({ SecretId: id })));
  const crumbs = [{ label: "Secrets Manager", href: "/secrets" }];
  if (!meta.ok) {
    return (
      <>
        <PageHeader title="Secret" crumbs={crumbs} />
        <ErrorNotice error={meta.error} />
      </>
    );
  }
  const s = meta.value;
  const value = reveal ? await load(() => client.send(new GetSecretValueCommand({ SecretId: id }))) : null;
  const self = `/secrets/secret?id=${encodeURIComponent(id)}`;
  return (
    <>
      <PageHeader title={s.Name} crumbs={crumbs} description={<code>{s.ARN}</code>} />
      <Section title="Details">
        <KeyValue
          items={[
            ["Description", s.Description],
            ["Encryption key", s.KmsKeyId ?? "aws/secretsmanager"],
            ["Rotation", s.RotationEnabled ? `every ${s.RotationRules?.AutomaticallyAfterDays} days via ${s.RotationLambdaARN}` : "off"],
            ["Last rotated", when(s.LastRotatedDate)],
            ["Last changed", when(s.LastChangedDate)],
            ["Created", when(s.CreatedDate)],
            [
              "Versions",
              <span className="chips">
                {Object.entries(s.VersionIdsToStages ?? {}).map(([v, stages]) => (
                  <Badge key={v} tone={stages.includes("AWSCURRENT") ? "good" : "neutral"}>
                    {stages.join(", ")}: {v.slice(0, 8)}
                  </Badge>
                ))}
              </span>,
            ],
          ]}
        />
      </Section>
      <Section title="Value" actions={!reveal && <Link className="button primary" href={`${self}&reveal=1`}>Reveal value</Link>}>
        {value === null ? (
          <p className="muted">Hidden. Revealing calls GetSecretValue, which shows up in the secret&apos;s last accessed date.</p>
        ) : value.ok ? (
          value.value.SecretString !== undefined ? (
            <CodeBlock value={value.value.SecretString} label="Secret value" />
          ) : (
            <p className="muted">Binary secret ({value.value.SecretBinary?.length ?? 0} bytes).</p>
          )
        ) : (
          <ErrorNotice error={value.error} />
        )}
      </Section>
      <Section title="Store a new value">
        <ActionForm action={putValue.bind(null, id)} submit="Put secret value" testId="put-secret-value">
          <Field label="New value" hint="Becomes AWSCURRENT; the old value becomes AWSPREVIOUS.">
            <textarea name="value" required />
          </Field>
        </ActionForm>
      </Section>
      <Section title="Delete">
        <ActionForm action={deleteSecret.bind(null, id)} submit="Delete secret" tone="danger" confirm={`Delete ${s.Name}?`} inline>
          <label className="check">
            <input type="checkbox" name="force" /> Without a recovery window
          </label>
        </ActionForm>
      </Section>
    </>
  );
}

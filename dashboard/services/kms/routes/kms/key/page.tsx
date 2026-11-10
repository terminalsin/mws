import { DescribeKeyCommand, GetKeyPolicyCommand, GetKeyRotationStatusCommand, ListResourceTagsCommand } from "@aws-sdk/client-kms";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, ErrorNotice, Facts, Field, List, Page, Pill, Section, Sheet, Status, Tags } from "@mws-dashboard/ui";
import { CalendarX, Pencil, Play, Power, RotateCw, Tag, Trash2, Undo2, Wand2, Plus } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, kms } from "../../../lib/clients";
import { STATE_TONE, listAliases } from "../../../lib/kms";
import { ALIAS, PENDING_DAYS, POLICY, TAGS, messageRule, takenAliases, tryAlgorithm } from "../../../lib/rules";
import { addAlias, cancelDeletion, deleteAlias, saveKeyPolicy, saveKeyTags, scheduleDeletion, setEnabled, setRotation, tryKey } from "../actions";

type Props = { searchParams: Promise<{ id?: string }> };

export const metadata: Metadata = { title: "Key" };

export default async function Key({ searchParams }: Props) {
  const { id = "" } = await searchParams;
  const back = { href: "/kms", label: "Keys" };
  const data = await load(async () => {
    const client = await kms();
    const meta = (await client.send(new DescribeKeyCommand({ KeyId: id }))).KeyMetadata!;
    const customer = meta.KeyManager === "CUSTOMER";
    const [all, policy, rotation, tags] = await Promise.all([
      listAliases(),
      client.send(new GetKeyPolicyCommand({ KeyId: meta.KeyId, PolicyName: "default" })).then((r) => r.Policy, () => undefined),
      meta.KeySpec === "SYMMETRIC_DEFAULT" && meta.Origin === "AWS_KMS"
        ? client.send(new GetKeyRotationStatusCommand({ KeyId: meta.KeyId })).then((r) => r, () => undefined)
        : undefined,
      customer ? client.send(new ListResourceTagsCommand({ KeyId: meta.KeyId })).then((r) => r.Tags ?? [], () => []) : [],
    ]);
    const aliases = all.filter((a) => a.TargetKeyId === meta.KeyId);
    return { meta, customer, aliases, taken: takenAliases(all.map((a) => a.AliasName!)), policy, rotation, tags };
  });
  if (!data.ok) {
    return (
      <Page title="Key" icon={ICONS.key} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { meta, customer, aliases, taken, policy, rotation, tags } = data.value;
  const keyId = meta.KeyId!;
  const state = meta.KeyState!;
  const usable = state === "Enabled";
  const algorithm = tryAlgorithm(meta);
  const title = aliases[0]?.AliasName?.replace(/^alias\//, "") ?? keyId;

  const actions = customer && (
    <>
      {state === "PendingDeletion" ? (
        <ActionForm action={cancelDeletion.bind(null, keyId)} submit="Cancel deletion" icon={<Undo2 size={16} />} testId="cancel-deletion" />
      ) : (
        <>
          <ActionForm
            action={setEnabled.bind(null, keyId, !usable)}
            submit={usable ? "Disable key" : "Enable key"}
            icon={usable ? <Power size={16} /> : <Play size={16} />}
            testId="toggle-key"
          />
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

  return (
    <Page title={title} icon={ICONS.key} back={back} subtitle={meta.Arn} actions={actions}>
      <Facts
        items={[
          ["State", state === "PendingDeletion" ? <Pill tone="bad">deletes {ago(meta.DeletionDate)}</Pill> : <Status tone={STATE_TONE[state] ?? "neutral"}>{state}</Status>],
          meta.KeySpec !== "SYMMETRIC_DEFAULT" && ["Spec", meta.KeySpec],
          meta.Description && ["Description", meta.Description],
          rotation && [
            "Rotation",
            customer ? (
              <ActionForm
                action={setRotation.bind(null, keyId, !rotation.KeyRotationEnabled)}
                submit={rotation.KeyRotationEnabled ? "Turn rotation off" : "Turn rotation on"}
                icon={<RotateCw size={15} />}
                tone={rotation.KeyRotationEnabled ? "primary" : "plain"}
                testId="toggle-rotation"
              />
            ) : (
              <RotateCw size={15} aria-label="Rotates yearly" />
            ),
          ],
          rotation?.KeyRotationEnabled && rotation.NextRotationDate && ["Next rotation", ago(rotation.NextRotationDate)],
          meta.MultiRegion && ["Multi-Region", meta.MultiRegionConfiguration?.MultiRegionKeyType],
          meta.Origin !== "AWS_KMS" && ["Origin", meta.Origin],
          ["Created", ago(meta.CreationDate)],
          tags.length > 0 && ["Tags", <Tags key="t" tags={tags.map((t) => ({ Key: t.TagKey, Value: t.TagValue }))} />],
        ]}
      />

      {usable && (
        <Section title={meta.KeyUsage === "ENCRYPT_DECRYPT" ? "Encrypt" : meta.KeyUsage === "SIGN_VERIFY" ? "Sign" : "MAC"} icon={<Wand2 size={16} />}>
          <ActionForm action={tryKey.bind(null, keyId, meta.KeyUsage!, algorithm)} submit="Run" inline testId="try-key">
            <Field label={meta.KeyUsage === "ENCRYPT_DECRYPT" ? "Plaintext" : "Message"} rule={messageRule(meta.KeyUsage!, meta.KeySpec!, algorithm)}>
              <input name="plaintext" placeholder="hello" required />
            </Field>
          </ActionForm>
        </Section>
      )}

      {customer && (
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
            rows={aliases.map((a) => ({
              key: a.AliasName!,
              title: a.AliasName,
              actions: <ActionForm action={deleteAlias.bind(null, keyId, a.AliasName!)} submit={`Remove ${a.AliasName}`} icon={<Trash2 size={15} />} tone="danger" />,
            }))}
          />
        </Section>
      )}

      <Section
        title="Key policy"
        actions={
          customer && (
            <>
              <Sheet title="Tags" label="Edit tags" icon={<Tag size={16} />} testId="edit-tags">
                <ActionForm action={saveKeyTags.bind(null, keyId)} submit="Save" testId="edit-tags">
                  <Field label="Tags" rule={TAGS}>
                    <textarea name="tags" rows={6} placeholder="team=payments" defaultValue={tags.map((t) => `${t.TagKey}=${t.TagValue}`).join("\n")} />
                  </Field>
                </ActionForm>
              </Sheet>
              <Sheet title="Key policy" label="Edit key policy" icon={<Pencil size={16} />} testId="edit-key-policy">
                <ActionForm action={saveKeyPolicy.bind(null, keyId)} submit="Save" testId="edit-key-policy">
                  <Field label="Key policy" rule={POLICY}>
                    <textarea name="policy" rows={16} defaultValue={pretty(policy)} />
                  </Field>
                </ActionForm>
              </Sheet>
            </>
          )
        }
      >
        <CodeBlock value={policy} label="Key policy" />
      </Section>
    </Page>
  );
}

function pretty(doc: string | undefined) {
  try {
    return JSON.stringify(JSON.parse(doc ?? ""), null, 2);
  } catch {
    return doc ?? "";
  }
}

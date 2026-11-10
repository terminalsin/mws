import { GetChallengePasswordCommand, GetConnectorCommand, ListChallengeMetadataCommand, ListTagsForResourceCommand } from "@aws-sdk/client-pca-connector-scep";
import { ago, all, load, when } from "@mws-dashboard/aws";
import { ActionForm, Empty, ErrorNotice, Facts, Field, List, Page, Section, Sheet, Status, Tags } from "@mws-dashboard/ui";
import { CopyButton } from "@mws-dashboard/ui/client";
import { Eye, EyeOff, KeyRound, Plus, Tag, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, scep } from "../../../lib/clients";
import { CA_TONE } from "../../../lib/pca";
import { createChallenge, deleteChallenge, deleteConnector, saveTags } from "../connectors/actions";

export const metadata: Metadata = { title: "Connector for SCEP" };

type Props = { searchParams: Promise<{ arn?: string; reveal?: string }> };

export default async function Connector({ searchParams }: Props) {
  const { arn = "", reveal } = await searchParams;
  const back = { href: "/pca/connectors", label: "Connectors for SCEP" };
  const c = await scep();
  const data = await load(async () => {
    const k = (await c.send(new GetConnectorCommand({ ConnectorArn: arn }))).Connector!;
    const [challenges, tags] = await Promise.all([
      k.Type === "INTUNE" ? [] : all((NextToken) => c.send(new ListChallengeMetadataCommand({ ConnectorArn: arn, NextToken })), (r) => r.Challenges, (r) => r.NextToken),
      c.send(new ListTagsForResourceCommand({ ResourceArn: arn })).then((r) => r.Tags ?? {}, () => ({}) as Record<string, string>),
    ]);
    const password = reveal ? await load(() => c.send(new GetChallengePasswordCommand({ ChallengeArn: reveal })).then((r) => r.Password ?? "")) : null;
    return { k, challenges, tags, password };
  });
  if (!data.ok) {
    return (
      <Page title="Connector" icon={ICONS.ca} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { k, challenges, tags, password } = data.value;
  const self = `/pca/connector?arn=${encodeURIComponent(arn)}`;
  const intune = k.MobileDeviceManagement?.Intune;
  return (
    <Page
      title={k.Arn!.split("/").pop()}
      icon={ICONS.ca}
      back={back}
      subtitle={k.Arn}
      actions={
        <>
          <Sheet title="Tags" label="Edit tags" icon={<Tag size={16} />} testId="edit-tags">
            <ActionForm action={saveTags.bind(null, arn, Object.keys(tags))} submit="Save" testId="edit-tags">
              <Field label="Tags" format="tags">
                <textarea name="tags" rows={4} defaultValue={Object.entries(tags).map(([key, v]) => `${key}=${v}`).join("\n")} />
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteConnector.bind(null, arn)} submit="Delete connector" icon={<Trash2 size={16} />} tone="danger" confirm="Delete this connector? Devices can no longer enroll through it." testId="delete-connector" />
        </>
      }
    >
      <Facts
        items={[
          ["Status", <Status key="s" tone={CA_TONE[k.Status ?? ""] ?? "neutral"}>{k.Status?.toLowerCase()}</Status>],
          k.StatusReason && ["Reason", k.StatusReason],
          k.Endpoint && ["SCEP URL", <span key="e"><code>{k.Endpoint}</code> <CopyButton value={k.Endpoint} label="Copy SCEP URL" /></span>],
          ["Certificate authority", <Link key="ca" href={`/pca/ca?arn=${encodeURIComponent(k.CertificateAuthorityArn!)}`}>{k.CertificateAuthorityArn!.split("/").pop()}</Link>],
          ["Type", k.Type === "INTUNE" ? "Microsoft Intune" : "General purpose"],
          intune && ["Azure application", intune.AzureApplicationId],
          intune && ["Domain", intune.Domain],
          k.OpenIdConfiguration?.Issuer && ["OpenID issuer", k.OpenIdConfiguration.Issuer],
          k.CreatedAt && ["Created", when(k.CreatedAt)],
        ]}
      />
      {k.Type !== "INTUNE" && (
        <Section title="Challenge passwords" count={challenges.length} plain actions={<ActionForm action={createChallenge.bind(null, arn)} submit="Create challenge" icon={<Plus size={16} />} testId="create-challenge" />}>
          <List
            label="Challenges"
            empty={<Empty>Devices need a challenge password to enroll</Empty>}
            rows={challenges.map((ch) => ({
              key: ch.Arn!,
              icon: <KeyRound size={18} aria-hidden />,
              title: ch.Arn!.split("/").pop(),
              subtitle:
                ch.Arn === reveal && password ? (
                  password.ok ? (
                    <span>
                      <code data-testid="challenge-password">{password.value}</code> <CopyButton value={password.value} label="Copy password" />
                    </span>
                  ) : (
                    <span className="tone-bad">{password.error}</span>
                  )
                ) : ch.CreatedAt ? (
                  `created ${ago(ch.CreatedAt)}`
                ) : undefined,
              actions: (
                <>
                  {ch.Arn === reveal ? (
                    <Link className="icon-button primary" href={self} aria-label="Hide password" title="Hide">
                      <EyeOff size={15} />
                    </Link>
                  ) : (
                    <Link className="icon-button plain" href={`${self}&reveal=${encodeURIComponent(ch.Arn!)}`} aria-label={`Show password of ${ch.Arn!.split("/").pop()}`} title="Show password">
                      <Eye size={15} />
                    </Link>
                  )}
                  <ActionForm action={deleteChallenge.bind(null, ch.Arn!)} submit={`Delete challenge ${ch.Arn!.split("/").pop()}`} icon={<Trash2 size={15} />} tone="danger" confirm="Delete this challenge?" />
                </>
              ),
            }))}
          />
        </Section>
      )}
      {Object.keys(tags).length > 0 && <Tags tags={tags} />}
    </Page>
  );
}

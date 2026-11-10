import { GetResourceShareInvitationsCommand, GetResourceSharesCommand } from "@aws-sdk/client-ram";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Status } from "@mws-dashboard/ui";
import { Check, Globe, X } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ram } from "../../lib/clients";
import { answerInvitation, createShare } from "./actions";

export const metadata: Metadata = { title: "RAM" };

type Props = { searchParams: Promise<{ tab?: string }> };

export default async function Shares({ searchParams }: Props) {
  const { tab = "mine" } = await searchParams;
  const client = await ram();
  const owner = tab === "others" ? "OTHER-ACCOUNTS" : "SELF";
  const [shares, invitations] = await Promise.all([
    load(async () => ((await client.send(new GetResourceSharesCommand({ resourceOwner: owner }))).resourceShares ?? []).filter((s) => s.status !== "DELETED")),
    load(async () => ((await client.send(new GetResourceShareInvitationsCommand({}))).resourceShareInvitations ?? []).filter((i) => i.status === "PENDING")),
  ]);
  const create = (
    <Sheet title="Create resource share" label="Create resource share" testId="create-share">
      <ActionForm action={createShare} submit="Create resource share" testId="create-share">
        <Field label="Name">
          <input name="name" required autoFocus />
        </Field>
        <Field label="Resource ARNs">
          <textarea name="resources" rows={3} placeholder="arn:aws:acm-pca:…:certificate-authority/…" />
        </Field>
        <Field label="Principals">
          <textarea name="principals" rows={2} placeholder="111122223333 or an OU / organization ARN" />
        </Field>
        <label className="check">
          <input type="checkbox" name="external" /> Allow sharing outside the organization
        </label>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title={tab === "others" ? "Shared with me" : "Shared by me"} actions={tab === "others" ? undefined : create}>
      {invitations.ok && invitations.value.length > 0 && (
        <Section title="Pending invitations" count={invitations.value.length} plain>
          <List
            label="Invitations"
            rows={invitations.value.map((i) => ({
              key: i.resourceShareInvitationArn!,
              icon: <AwsIcon icon={ICONS.ram} size={22} />,
              title: i.resourceShareName,
              subtitle: `from ${i.senderAccountId}`,
              meta: <span>{ago(i.invitationTimestamp)}</span>,
              actions: (
                <>
                  <ActionForm action={answerInvitation.bind(null, i.resourceShareInvitationArn!, true)} submit={`Accept ${i.resourceShareName}`} icon={<Check size={15} />} />
                  <ActionForm action={answerInvitation.bind(null, i.resourceShareInvitationArn!, false)} submit={`Reject ${i.resourceShareName}`} icon={<X size={15} />} tone="danger" />
                </>
              ),
            }))}
          />
        </Section>
      )}
      {shares.ok ? (
        <List
          label="Resource shares"
          empty={<Empty icon={ICONS.ram} action={tab === "others" ? undefined : create} />}
          rows={shares.value.map((s) => ({
            key: s.resourceShareArn!,
            icon: <AwsIcon icon={ICONS.ram} size={22} />,
            title: s.name,
            subtitle: tab === "others" ? `from ${s.owningAccountId}` : undefined,
            href: `/ram/share?arn=${encodeURIComponent(s.resourceShareArn!)}`,
            meta: (
              <>
                {s.allowExternalPrincipals && <Globe size={13} aria-label="External principals allowed" />}
                {s.featureSet && s.featureSet !== "STANDARD" && <Pill>{s.featureSet.toLowerCase()}</Pill>}
                <Status tone={s.status === "ACTIVE" ? "good" : "warn"}>{s.status?.toLowerCase()}</Status>
                <span>{ago(s.creationTime)}</span>
              </>
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={shares.error} />
      )}
    </Page>
  );
}

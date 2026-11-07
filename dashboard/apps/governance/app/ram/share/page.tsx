import { GetResourceSharesCommand, ListPrincipalsCommand, ListResourcesCommand } from "@aws-sdk/client-ram";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, List, Page, Section, Specs, Status, Tags, SERVICES } from "@mws-dashboard/ui";
import { Globe, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ram } from "../../../lib/clients";
import { deleteShare } from "../actions";

export const metadata: Metadata = { title: "Resource share" };

type Props = { searchParams: Promise<{ arn?: string }> };

const iconFor = (type: string | undefined) => {
  const svc = type?.split(":")[0] ?? "";
  return SERVICES.find((s) => s.id === svc.replace("-", "") || s.endpoints.includes(svc))?.icon ?? ICONS.ram;
};

export default async function Share({ searchParams }: Props) {
  const { arn = "" } = await searchParams;
  const back = { href: "/ram", label: "Shared by me" };
  const data = await load(async () => {
    const client = await ram();
    const owned = (await client.send(new GetResourceSharesCommand({ resourceOwner: "SELF", resourceShareArns: [arn] }))).resourceShares?.[0];
    const owner = owned ? "SELF" : "OTHER-ACCOUNTS";
    const share = owned ?? (await client.send(new GetResourceSharesCommand({ resourceOwner: "OTHER-ACCOUNTS", resourceShareArns: [arn] }))).resourceShares![0];
    const [resources, principals] = await Promise.all([
      client.send(new ListResourcesCommand({ resourceOwner: owner, resourceShareArns: [arn] })).then((r) => r.resources ?? []),
      owned ? client.send(new ListPrincipalsCommand({ resourceOwner: "SELF", resourceShareArns: [arn] })).then((r) => r.principals ?? []) : [],
    ]);
    return { share, resources, principals, owned: !!owned };
  });
  if (!data.ok) {
    return (
      <Page title="Resource share" icon={ICONS.ram} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { share, resources, principals, owned } = data.value;
  return (
    <Page
      title={share.name}
      icon={ICONS.ram}
      back={back}
      subtitle={arn}
      actions={owned ? <ActionForm action={deleteShare.bind(null, arn)} submit="Delete resource share" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${share.name}?`} testId="delete-share" /> : undefined}
    >
      <Specs
        items={[
          { label: "Status", icon: <AwsIcon icon={ICONS.ram} size={16} />, value: <Status tone={share.status === "ACTIVE" ? "good" : "warn"}>{share.status?.toLowerCase()}</Status> },
          share.allowExternalPrincipals && { label: "External principals", icon: <Globe size={15} />, value: "Allowed" },
          !owned && { label: "Owner", icon: <AwsIcon icon={ICONS.account} size={16} />, value: share.owningAccountId },
        ]}
      />
      <Section title="Shared resources" count={resources.length} plain>
        <List
          label="Shared resources"
          empty={<Empty icon={ICONS.ram} />}
          rows={resources.map((r) => ({
            key: r.arn!,
            icon: <AwsIcon icon={iconFor(r.type)} size={22} />,
            title: r.arn!.split(/[:/]/).pop(),
            subtitle: r.type,
            meta: <Status tone={r.status === "AVAILABLE" ? "good" : "warn"}>{r.status?.toLowerCase()}</Status>,
          }))}
        />
      </Section>
      {owned && (
        <Section title="Principals" count={principals.length} plain>
          <List
            label="Principals"
            empty={<Empty icon={ICONS.account} />}
            rows={principals.map((p) => ({
              key: p.id!,
              icon: <AwsIcon icon={/^\d{12}$/.test(p.id ?? "") ? ICONS.account : p.id?.includes(":ou/") ? ICONS.ou : ICONS.organizations} size={22} />,
              title: p.id,
              meta: p.external ? <Globe size={13} aria-label="External" /> : undefined,
            }))}
          />
        </Section>
      )}
      <Tags tags={share.tags?.map((t) => ({ Key: t.key, Value: t.value }))} />
    </Page>
  );
}

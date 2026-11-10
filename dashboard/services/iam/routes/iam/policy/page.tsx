import { GetPolicyCommand, GetPolicyVersionCommand, ListEntitiesForPolicyCommand } from "@aws-sdk/client-iam";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, List, Page, Section } from "@mws-dashboard/ui";
import { Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, iam, policyDocument } from "../../../lib/clients";
import { deletePolicy } from "../actions";

type Props = { searchParams: Promise<{ arn?: string }> };

export async function generateMetadata({ searchParams }: Props): Promise<Metadata> {
  return { title: (await searchParams).arn?.split("/").pop() ?? "Policy" };
}

export default async function Policy({ searchParams }: Props) {
  const { arn = "" } = await searchParams;
  const name = arn.split("/").pop() ?? arn;
  const back = { href: "/iam?tab=policies", label: "Policies" };
  const data = await load(async () => {
    const client = await iam();
    const policy = (await client.send(new GetPolicyCommand({ PolicyArn: arn }))).Policy!;
    const [version, entities] = await Promise.all([
      client.send(new GetPolicyVersionCommand({ PolicyArn: arn, VersionId: policy.DefaultVersionId })),
      client.send(new ListEntitiesForPolicyCommand({ PolicyArn: arn })),
    ]);
    return { policy, document: policyDocument(version.PolicyVersion?.Document), entities };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.policy} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { policy, document, entities } = data.value;
  const aws = arn.includes(":aws:policy/");
  const attached = [
    ...(entities.PolicyRoles ?? []).map((r) => ({ key: `r:${r.RoleId}`, icon: ICONS.role, title: r.RoleName!, href: `/iam/roles/${encodeURIComponent(r.RoleName!)}` })),
    ...(entities.PolicyUsers ?? []).map((u) => ({ key: `u:${u.UserId}`, icon: ICONS.user, title: u.UserName!, href: `/iam/users/${encodeURIComponent(u.UserName!)}` })),
    ...(entities.PolicyGroups ?? []).map((g) => ({ key: `g:${g.GroupId}`, icon: ICONS.users, title: g.GroupName!, href: `/iam/groups/${encodeURIComponent(g.GroupName!)}` })),
  ];
  return (
    <Page
      title={policy.PolicyName}
      icon={ICONS.policy}
      back={back}
      subtitle={arn}
      actions={
        !aws && (
          <ActionForm
            action={deletePolicy.bind(null, arn)}
            submit="Delete policy"
            icon={<Trash2 size={16} />}
            tone="danger"
            confirm={`Delete ${policy.PolicyName}?`}
            testId="delete-policy"
          />
        )
      }
    >
      <Facts
        items={[
          policy.Description && ["Description", policy.Description],
          ["Updated", ago(policy.UpdateDate)],
          policy.DefaultVersionId !== "v1" && ["Version", policy.DefaultVersionId],
        ]}
      />
      <Section title="Used by" count={attached.length} plain>
        <List
          label="Used by"
          empty={<Empty icon={ICONS.policy} />}
          rows={attached.map((a) => ({ key: a.key, icon: <AwsIcon icon={a.icon} size={22} />, title: a.title, href: a.href }))}
        />
      </Section>
      <Section title="Document">
        <CodeBlock value={document} label="Policy document" />
      </Section>
    </Page>
  );
}

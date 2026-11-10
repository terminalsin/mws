import { GetPolicyCommand, GetPolicyVersionCommand, ListPolicyTagsCommand } from "@aws-sdk/client-iam";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Tags } from "@mws-dashboard/ui";
import { CheckCircle2, Pencil, Tag, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, iam, policyDocument } from "../../../lib/clients";
import { policyEntities, policyVersions } from "../../../lib/iam";
import { RULES } from "../../../lib/rules";
import { createPolicyVersion, deletePolicy, deletePolicyVersion, saveTags, setDefaultVersion } from "../actions";

type Props = { searchParams: Promise<{ arn?: string; tab?: string; version?: string }> };

export async function generateMetadata({ searchParams }: Props): Promise<Metadata> {
  return { title: (await searchParams).arn?.split("/").pop() ?? "Policy" };
}

export default async function Policy({ searchParams }: Props) {
  const { arn = "", tab = "permissions", version } = await searchParams;
  const name = arn.split("/").pop() ?? arn;
  const back = { href: "/iam?tab=policies", label: "Policies" };
  const aws = arn.includes(":aws:policy/");
  const data = await load(async () => {
    const client = await iam();
    const policy = (await client.send(new GetPolicyCommand({ PolicyArn: arn }))).Policy!;
    const shown = version ?? policy.DefaultVersionId;
    const [doc, entities, versions, tags] = await Promise.all([
      client.send(new GetPolicyVersionCommand({ PolicyArn: arn, VersionId: shown })),
      policyEntities(client, arn),
      policyVersions(client, arn),
      aws
        ? []
        : all(
            (Marker) => client.send(new ListPolicyTagsCommand({ PolicyArn: arn, Marker })),
            (r) => r.Tags,
            (r) => (r.IsTruncated ? r.Marker : undefined),
          ),
    ]);
    return { policy, shown, document: policyDocument(doc.PolicyVersion?.Document), entities, versions, tags };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.policy} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { policy, shown, document, entities, versions, tags } = data.value;
  const base = `/iam/policy?arn=${encodeURIComponent(arn)}`;
  const attached = [
    ...entities.roles.map((r) => ({ key: `r:${r.RoleId}`, icon: ICONS.role, title: r.RoleName!, kind: "Role", href: `/iam/roles/${encodeURIComponent(r.RoleName!)}` })),
    ...entities.users.map((u) => ({ key: `u:${u.UserId}`, icon: ICONS.user, title: u.UserName!, kind: "User", href: `/iam/users/${encodeURIComponent(u.UserName!)}` })),
    ...entities.groups.map((g) => ({ key: `g:${g.GroupId}`, icon: ICONS.users, title: g.GroupName!, kind: "Group", href: `/iam/groups/${encodeURIComponent(g.GroupName!)}` })),
  ];
  const sorted = [...versions].sort((a, b) => +new Date(b.CreateDate!) - +new Date(a.CreateDate!));
  const oldest = [...sorted].reverse().find((v) => !v.IsDefaultVersion);
  const viewingOld = shown !== policy.DefaultVersionId;

  const tabs = [
    { id: "permissions", label: "Permissions" },
    { id: "entities", label: "Entities attached", count: attached.length },
    !aws && { id: "tags", label: "Tags", count: tags.length || undefined },
    { id: "versions", label: "Policy versions", count: versions.length },
  ].filter((t): t is { id: string; label: string; count: number | undefined } => !!t);
  const active = tabs.find((t) => t.id === tab)?.id ?? "permissions";

  let body;
  if (active === "entities") {
    body = (
      <Section title="Entities attached" count={attached.length} plain>
        <List
          label="Used by"
          empty={<Empty icon={ICONS.policy} />}
          rows={attached.map((a) => ({ key: a.key, icon: <AwsIcon icon={a.icon} size={22} />, title: a.title, subtitle: a.kind, href: a.href }))}
        />
      </Section>
    );
  } else if (active === "tags") {
    body = (
      <Section
        title="Tags"
        count={tags.length}
        actions={
          <Sheet title="Tags" label="Edit tags" icon={<Tag size={16} />} testId="edit-tags">
            <ActionForm action={saveTags.bind(null, "policy", arn, tags.map((t) => t.Key!))} submit="Save" testId="edit-tags">
              <Field label="Tags" format="tags">
                <textarea name="tags" rows={6} placeholder="team=payments" defaultValue={tags.map((t) => `${t.Key}=${t.Value}`).join("\n")} />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {tags.length ? <Tags tags={tags} /> : <Empty>No tags</Empty>}
      </Section>
    );
  } else if (active === "versions") {
    body = (
      <Section title="Policy versions" count={versions.length} plain>
        <List
          label="Policy versions"
          rows={sorted.map((v) => ({
            key: v.VersionId!,
            icon: v.IsDefaultVersion ? <CheckCircle2 size={18} aria-label="Default" /> : <Pencil size={18} />,
            title: v.VersionId,
            subtitle: v.IsDefaultVersion ? "Default version" : undefined,
            href: `${base}&version=${v.VersionId}`,
            meta: ago(v.CreateDate),
            actions: !aws && !v.IsDefaultVersion && (
              <>
                <ActionForm action={setDefaultVersion.bind(null, arn, v.VersionId!)} submit={`Set ${v.VersionId} as default`} icon={<CheckCircle2 size={15} />} />
                <ActionForm action={deletePolicyVersion.bind(null, arn, v.VersionId!)} submit={`Delete ${v.VersionId}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${v.VersionId}?`} />
              </>
            ),
          }))}
        />
      </Section>
    );
  } else {
    body = (
      <Section
        title={viewingOld ? `Version ${shown}` : "Permissions defined in this policy"}
        actions={
          viewingOld && !aws ? (
            <ActionForm action={setDefaultVersion.bind(null, arn, shown!)} submit={`Set ${shown} as default`} icon={<CheckCircle2 size={16} />} testId="set-default-version" />
          ) : undefined
        }
      >
        <CodeBlock value={document} label="Policy document" />
      </Section>
    );
  }

  return (
    <Page
      title={policy.PolicyName}
      icon={ICONS.policy}
      back={back}
      subtitle={arn}
      actions={
        !aws && (
          <>
            <Sheet title={`Edit ${policy.PolicyName}`} label="Edit policy" icon={<Pencil size={16} />} testId="edit-policy">
              <ActionForm action={createPolicyVersion.bind(null, arn)} submit="Save changes" testId="edit-policy">
                <Field
                  label="Document"
                  rule={RULES.document}
                  hint={versions.length >= 5 && oldest ? `Saving deletes ${oldest.VersionId}, the oldest version: IAM keeps five` : undefined}
                >
                  <textarea name="document" rows={16} required aria-label="Policy document" defaultValue={pretty(document)} />
                </Field>
                <label className="check">
                  <input type="checkbox" name="default" defaultChecked /> Set as default version
                </label>
              </ActionForm>
            </Sheet>
            <ActionForm
              action={deletePolicy.bind(null, arn)}
              submit="Delete policy"
              icon={<Trash2 size={16} />}
              tone="danger"
              confirm={attached.length ? `Delete ${policy.PolicyName}? It is detached from ${attached.length} entities first.` : `Delete ${policy.PolicyName}?`}
              testId="delete-policy"
            />
          </>
        )
      }
    >
      <Facts
        items={[
          ["Type", aws ? "AWS managed" : "Customer managed"],
          policy.Description && ["Description", policy.Description],
          ["Default version", policy.DefaultVersionId],
          ["Attached", (policy.AttachmentCount ?? 0) > 0 ? policy.AttachmentCount : <Pill key="u" tone="warn">unattached</Pill>],
          policy.PermissionsBoundaryUsageCount ? ["Used as boundary", policy.PermissionsBoundaryUsageCount] : null,
          ["Updated", ago(policy.UpdateDate)],
          ["Created", ago(policy.CreateDate)],
        ]}
      />
      <Segments
        label="Policy tabs"
        items={tabs.map((t) => ({ label: t.label, href: t.id === "permissions" ? base : `${base}&tab=${t.id}`, active: active === t.id, count: t.count }))}
      />
      {body}
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

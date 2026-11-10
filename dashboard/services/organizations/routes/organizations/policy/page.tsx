import { DescribePolicyCommand, ListTagsForResourceCommand } from "@aws-sdk/client-organizations";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Sheet, Tags, type Rule } from "@mws-dashboard/ui";
import { CreatePolicy, UpdatePolicy } from "@mws-dashboard/ui/model/organizations";
import { Pencil, Plus, Tag, Trash2, Unlink } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, organizations } from "../../../lib/clients";
import { POLICY_TYPES, flatten, orgTree, policyLimit, targetsForPolicy } from "../../../lib/organizations";
import { attachPolicy, deletePolicy, detachPolicy, saveTags, updatePolicy } from "../actions";

type Props = { searchParams: Promise<{ id?: string }> };

export const metadata: Metadata = { title: "Policy" };

const TARGET_ICON: Record<string, string> = { ROOT: ICONS.organizations, ORGANIZATIONAL_UNIT: ICONS.ou, ACCOUNT: ICONS.account };

/** One organization policy: its content, edited in place, and where it applies. */
export default async function Policy({ searchParams }: Props) {
  const { id = "" } = await searchParams;
  const data = await load(async () => {
    const client = await organizations();
    const [policy, targets, tree, tags] = await Promise.all([
      client.send(new DescribePolicyCommand({ PolicyId: id })).then((r) => r.Policy!),
      targetsForPolicy(client, id),
      orgTree(),
      client.send(new ListTagsForResourceCommand({ ResourceId: id })).then((r) => r.Tags ?? [], () => []),
    ]);
    return { policy, targets, nodes: flatten(tree.tree).map((x) => x.node), tags };
  });
  if (!data.ok) {
    return (
      <Page title="Policy" icon={ICONS.policy} back={{ href: "/organizations?tab=policies", label: "Policies" }}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { policy, targets, nodes, tags } = data.value;
  const s = policy.PolicySummary!;
  const kind = POLICY_TYPES.find((t) => t.type === s.Type);
  const back = { href: `/organizations?tab=policies&type=${s.Type}`, label: kind?.label ?? "Policies" };
  const attached = new Set(targets.map((t) => t.TargetId));
  const path = `/organizations/policy?id=${id}`;
  const content: Rule = { ...UpdatePolicy.Content, format: "json", maxLength: policyLimit(s.Type!) };
  return (
    <Page
      title={s.Name}
      icon={ICONS.policy}
      back={back}
      subtitle={s.Arn}
      actions={
        <>
          <Sheet title={`Attach ${s.Name}`} label="Attach" icon={<Plus size={16} />} testId="attach-policy">
            <ActionForm action={attachPolicy.bind(null, id)} submit="Attach" testId="attach-policy">
              <Field label="Target">
                <select name="target" required>
                  {nodes.flatMap((n) => [
                    <option key={n.id} value={n.id} disabled={attached.has(n.id)}>
                      {n.name}
                    </option>,
                    ...n.accounts
                      .filter((a) => !attached.has(a.Id))
                      .map((a) => (
                        <option key={a.Id} value={a.Id}>
                          {"  "}
                          {a.Name} ({a.Id})
                        </option>
                      )),
                  ])}
                </select>
              </Field>
            </ActionForm>
          </Sheet>
          {!s.AwsManaged && (
            <>
              <Sheet title="Tags" label="Edit tags" icon={<Tag size={16} />} testId="edit-tags">
                <ActionForm action={saveTags.bind(null, id, path)} submit="Save" testId="edit-tags">
                  <Field label="Tags" format="tags">
                    <textarea name="tags" rows={6} placeholder="team=security" defaultValue={tags.map((t) => `${t.Key}=${t.Value}`).join("\n")} />
                  </Field>
                </ActionForm>
              </Sheet>
              <Sheet title={`Edit ${s.Name}`} label="Edit policy" icon={<Pencil size={16} />} testId="edit-org-policy">
                <ActionForm action={updatePolicy.bind(null, id, s.Type!)} submit="Save changes" testId="edit-org-policy">
                  <Field label="Name" rule={UpdatePolicy.Name}>
                    <input name="name" required defaultValue={s.Name} />
                  </Field>
                  <Field label="Description" rule={{ ...CreatePolicy.Description, required: false }}>
                    <input name="description" defaultValue={s.Description} />
                  </Field>
                  <Field label="Policy" rule={content}>
                    <textarea name="content" rows={16} className="code-editor" defaultValue={pretty(policy.Content)} />
                  </Field>
                </ActionForm>
              </Sheet>
              <ActionForm
                action={deletePolicy.bind(null, id, targets.map((t) => t.TargetId!), back.href)}
                submit="Delete policy"
                icon={<Trash2 size={16} />}
                tone="danger"
                confirm={targets.length ? `Delete ${s.Name}? It is detached from ${targets.length} targets first.` : `Delete ${s.Name}?`}
                testId="delete-org-policy"
              />
            </>
          )}
        </>
      }
    >
      <Facts
        items={[
          ["Type", kind?.label ?? s.Type],
          s.AwsManaged && ["Managed by", "AWS"],
          s.Description && ["Description", s.Description],
          tags.length > 0 && ["Tags", <Tags key="t" tags={tags} />],
        ]}
      />
      <Section title="Targets" count={targets.length} plain>
        <List
          label="Targets"
          empty={<Empty icon={ICONS.policy}>{<Pill tone="warn">unattached</Pill>}</Empty>}
          rows={targets.map((t) => ({
            key: t.TargetId!,
            icon: <AwsIcon icon={TARGET_ICON[t.Type!] ?? ICONS.ou} size={22} />,
            title: t.Name,
            subtitle: t.TargetId,
            href: t.Type === "ACCOUNT" ? `/organizations/accounts/${t.TargetId}` : "/organizations",
            actions: <ActionForm action={detachPolicy.bind(null, id, t.TargetId!)} submit={`Detach from ${t.Name}`} icon={<Unlink size={15} />} confirm={`Detach ${s.Name} from ${t.Name}?`} />,
          }))}
        />
      </Section>
      <Section title="Content">
        <CodeBlock value={policy.Content} label="Policy content" />
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

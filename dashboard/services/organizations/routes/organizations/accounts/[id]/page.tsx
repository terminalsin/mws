import { DescribeAccountCommand, DescribeOrganizationCommand, ListDelegatedServicesForAccountCommand, ListParentsCommand, ListRootsCommand, ListTagsForResourceCommand } from "@aws-sdk/client-organizations";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Sheet, Status, Tags } from "@mws-dashboard/ui";
import { ArrowRightLeft, DoorOpen, Plus, Power, Shield, Tag, Unlink } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, organizations } from "../../../../lib/clients";
import { POLICY_TYPES, flatten, orgTree, policiesForTarget, policiesOfType } from "../../../../lib/organizations";
import { attachToTarget, closeAccount, detachPolicy, moveAccount, removeAccount, saveTags } from "../../actions";

type Props = { params: Promise<{ id: string }> };

export const metadata: Metadata = { title: "AWS account" };

const STATE_TONE: Record<string, "good" | "warn" | "bad"> = { ACTIVE: "good", PENDING_CLOSURE: "warn", SUSPENDED: "warn", CLOSED: "bad", PENDING_ACTIVATION: "warn" };

/** One member account: who it is, where it sits, which policies apply to it. */
export default async function AccountPage({ params }: Props) {
  const { id } = await params;
  const back = { href: "/organizations", label: "AWS accounts" };
  const data = await load(async () => {
    const client = await organizations();
    const [account, org, parents, tags, delegated, tree, roots] = await Promise.all([
      client.send(new DescribeAccountCommand({ AccountId: id })).then((r) => r.Account!),
      client.send(new DescribeOrganizationCommand({})).then((r) => r.Organization!),
      all((NextToken) => client.send(new ListParentsCommand({ ChildId: id, NextToken })), (r) => r.Parents, (r) => r.NextToken),
      client.send(new ListTagsForResourceCommand({ ResourceId: id })).then((r) => r.Tags ?? []),
      all((NextToken) => client.send(new ListDelegatedServicesForAccountCommand({ AccountId: id, NextToken })), (r) => r.DelegatedServices, (r) => r.NextToken).catch(() => []),
      orgTree(),
      all((NextToken) => client.send(new ListRootsCommand({ NextToken })), (r) => r.Roots, (r) => r.NextToken),
    ]);
    // Policies attached directly, for every policy type the root has on.
    const types = POLICY_TYPES.filter((t) => roots[0]?.PolicyTypes?.some((p) => p.Type === t.type && p.Status === "ENABLED"));
    const [direct, available] = await Promise.all([
      Promise.all(types.map(async (t) => (await policiesForTarget(client, id, t.type)).map((p) => ({ ...p, kind: t.short })))).then((x) => x.flat()),
      Promise.all(types.map(async (t) => (await policiesOfType(client, t.type)).map((p) => ({ ...p, kind: t.short })))).then((x) => x.flat()),
    ]);
    return { account, org, parents, tags, delegated, nodes: flatten(tree.tree).map((x) => x.node), direct, available };
  });
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.account} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { account: a, org, parents, tags, delegated, nodes, direct, available } = data.value;
  const management = a.Id === org.MasterAccountId;
  const state = a.State ?? a.Status ?? "ACTIVE";
  const parent = parents[0];
  const parentName = nodes.find((n) => n.id === parent?.Id)?.name ?? parent?.Id;
  const attached = new Set(direct.map((p) => p.Id));
  const path = `/organizations/accounts/${id}`;

  return (
    <Page
      title={a.Name}
      icon={management ? ICONS.management : ICONS.account}
      back={back}
      subtitle={a.Arn}
      actions={
        <>
          {parent && (
            <Sheet title={`Move ${a.Name}`} label="Move" icon={<ArrowRightLeft size={16} />} testId="move-account">
              <ActionForm action={moveAccount.bind(null, id, parent.Id!)} submit="Move" testId="move-account">
                <Field label="Destination">
                  <select name="to" required>
                    {nodes
                      .filter((n) => n.id !== parent.Id)
                      .map((n) => (
                        <option key={n.id} value={n.id}>
                          {n.name}
                        </option>
                      ))}
                  </select>
                </Field>
              </ActionForm>
            </Sheet>
          )}
          <Sheet title="Tags" label="Edit tags" icon={<Tag size={16} />} testId="edit-tags">
            <ActionForm action={saveTags.bind(null, id, path)} submit="Save" testId="edit-tags">
              <Field label="Tags" format="tags">
                <textarea name="tags" rows={6} placeholder="env=prod" defaultValue={tags.map((t) => `${t.Key}=${t.Value}`).join("\n")} />
              </Field>
            </ActionForm>
          </Sheet>
          {!management && state === "ACTIVE" && (
            <>
              <ActionForm
                action={removeAccount.bind(null, id)}
                submit="Remove from organization"
                icon={<DoorOpen size={16} />}
                tone="danger"
                confirm={`Remove ${a.Name} from the organization? It becomes a standalone account.`}
                testId="remove-account"
              />
              <ActionForm
                action={closeAccount.bind(null, id)}
                submit="Close account"
                icon={<Power size={16} />}
                tone="danger"
                confirm={`Close ${a.Name}? It is suspended now and closed after 90 days.`}
                testId="close-account"
              />
            </>
          )}
        </>
      }
    >
      <Facts
        items={[
          ["Status", <Status key="s" tone={STATE_TONE[state] ?? "warn"}>{state.toLowerCase().replace(/_/g, " ")}</Status>],
          management && ["Role", <Pill key="m" tone="info">Management account</Pill>],
          ["Email", a.Email],
          parent && [
            "Parent",
            <Link key="p" href="/organizations">
              {parentName}
            </Link>,
          ],
          a.JoinedMethod && ["Joined", `${a.JoinedMethod === "CREATED" ? "created" : "invited"} ${ago(a.JoinedTimestamp)}`],
          delegated.length > 0 && ["Delegated administrator for", delegated.map((d) => d.ServicePrincipal).join(", ")],
          ["Identity Center", <Link key="ic" href={`/identitycenter/accounts/${id}`}>Assignments</Link>],
          tags.length > 0 && ["Tags", <Tags key="t" tags={tags} />],
        ]}
      />
      <Section
        title="Policies"
        count={direct.length}
        plain
        actions={
          <Sheet title="Attach policy" label="Attach policy" icon={<Plus size={16} />} testId="attach-account-policy">
            <ActionForm action={attachToTarget.bind(null, id)} submit="Attach" testId="attach-account-policy">
              <Field label="Policy">
                <select name="policy" required>
                  {available
                    .filter((p) => !attached.has(p.Id))
                    .map((p) => (
                      <option key={p.Id} value={p.Id}>
                        {p.Name} ({p.kind})
                      </option>
                    ))}
                </select>
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        <List
          label="Attached policies"
          empty={<Empty icon={ICONS.policy} />}
          rows={direct.map((p) => ({
            key: p.Id!,
            icon: <Shield size={18} />,
            title: p.Name,
            subtitle: p.kind + (p.AwsManaged ? " · AWS managed" : ""),
            href: `/organizations/policy?id=${p.Id}`,
            actions: <ActionForm action={detachPolicy.bind(null, p.Id!, id)} submit={`Detach ${p.Name}`} icon={<Unlink size={15} />} confirm={`Detach ${p.Name} from ${a.Name}?`} />,
          }))}
        />
      </Section>
    </Page>
  );
}

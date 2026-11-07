import { ListPoliciesCommand, ListTargetsForPolicyCommand, type Account } from "@aws-sdk/client-organizations";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Status } from "@mws-dashboard/ui";
import { ArrowRightLeft, FolderPlus, Plus, Shield, Trash2, X } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, organizations } from "../../lib/clients";
import { flatten, orgTree, type OrgNode } from "../../lib/organizations";
import { attachPolicy, createAccount, createOrganization, createOu, createPolicy, deleteOu, deletePolicy, detachPolicy, moveAccount } from "./actions";

export const metadata: Metadata = { title: "Organizations" };

type Props = { searchParams: Promise<{ tab?: string }> };

const DENY_REGIONS = JSON.stringify(
  {
    Version: "2012-10-17",
    Statement: [{ Sid: "DenyOutsideRegions", Effect: "Deny", NotAction: ["iam:*", "organizations:*", "sts:*"], Resource: "*", Condition: { StringNotEquals: { "aws:RequestedRegion": ["us-east-1"] } } }],
  },
  null,
  2,
);

function Tree({ node, all, management }: { node: OrgNode; all: OrgNode[]; management: string | undefined }) {
  const accountRow = (a: Account) => (
    <li key={a.Id} className="tree-row">
      <AwsIcon icon={a.Id === management ? ICONS.management : ICONS.account} size={20} />
      <span className="tree-name">{a.Name}</span>
      <code className="muted">{a.Id}</code>
      {a.Id === management && <Pill tone="info">Management</Pill>}
      {a.Status !== "ACTIVE" && <Status tone="warn">{a.Status?.toLowerCase()}</Status>}
      <span className="tree-email muted">{a.Email}</span>
      <Sheet title={`Move ${a.Name}`} label={`Move ${a.Name}`} icon={<ArrowRightLeft size={14} />} testId={`move-${a.Id}`}>
        <ActionForm action={moveAccount.bind(null, a.Id!, node.id)} submit="Move" testId={`move-${a.Id}`}>
          <Field label="Destination">
            <select name="to" required>
              {all
                .filter((n) => n.id !== node.id)
                .map((n) => (
                  <option key={n.id} value={n.id}>
                    {n.name}
                  </option>
                ))}
            </select>
          </Field>
        </ActionForm>
      </Sheet>
    </li>
  );
  return (
    <li className="tree-node">
      <div className="tree-row">
        <AwsIcon icon={node.kind === "root" ? ICONS.organizations : ICONS.ou} size={20} />
        <span className="tree-name">{node.name}</span>
        <code className="muted">{node.id}</code>
        {node.policies
          .filter((p) => p.Name !== "FullAWSAccess")
          .map((p) => (
            <Pill key={p.Id} icon={<Shield size={11} />}>
              {p.Name}
            </Pill>
          ))}
        {node.kind === "ou" && node.children.length === 0 && node.accounts.length === 0 && (
          <ActionForm action={deleteOu.bind(null, node.id)} submit={`Delete ${node.name}`} icon={<Trash2 size={14} />} tone="danger" confirm={`Delete ${node.name}?`} />
        )}
      </div>
      {(node.children.length > 0 || node.accounts.length > 0) && (
        <ul className="tree">
          {node.children.map((c) => (
            <Tree key={c.id} node={c} all={all} management={management} />
          ))}
          {node.accounts.map(accountRow)}
        </ul>
      )}
    </li>
  );
}

async function Policies({ targets }: { targets: OrgNode[] }) {
  const policies = await load(async () => {
    const client = await organizations();
    const list = (await client.send(new ListPoliciesCommand({ Filter: "SERVICE_CONTROL_POLICY" }))).Policies ?? [];
    return Promise.all(list.map(async (p) => ({ p, targets: (await client.send(new ListTargetsForPolicyCommand({ PolicyId: p.Id }))).Targets ?? [] })));
  });
  if (!policies.ok) return <ErrorNotice error={policies.error} />;
  return (
    <List
      label="Service control policies"
      rows={policies.value.map(({ p, targets: attached }) => ({
        key: p.Id!,
        icon: <AwsIcon icon={ICONS.policy} size={22} />,
        title: p.Name,
        subtitle: p.Description || undefined,
        meta: (
          <>
            {p.AwsManaged && <Pill>AWS managed</Pill>}
            {attached.map((t) => (
              <Pill key={t.TargetId} tone="info">
                {t.Name}
                {!p.AwsManaged && (
                  <ActionForm action={detachPolicy.bind(null, p.Id!, t.TargetId!)} submit={`Detach ${p.Name} from ${t.Name}`} icon={<X size={11} />} />
                )}
              </Pill>
            ))}
          </>
        ),
        actions: (
          <>
            <Sheet title={`Attach ${p.Name}`} label={`Attach ${p.Name}`} icon={<Plus size={15} />} testId={`attach-${p.Name}`}>
              <ActionForm action={attachPolicy.bind(null, p.Id!)} submit="Attach" testId={`attach-${p.Name}`}>
                <Field label="Target">
                  <select name="target">
                    {targets.flatMap((n) => [
                      <option key={n.id} value={n.id}>
                        {n.name}
                      </option>,
                      ...n.accounts.map((a) => (
                        <option key={a.Id} value={a.Id}>
                          {"  "}
                          {a.Name}
                        </option>
                      )),
                    ])}
                  </select>
                </Field>
              </ActionForm>
            </Sheet>
            {!p.AwsManaged && <ActionForm action={deletePolicy.bind(null, p.Id!)} submit={`Delete ${p.Name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${p.Name}?`} />}
          </>
        ),
      }))}
    />
  );
}

export default async function Organization({ searchParams }: Props) {
  const { tab = "accounts" } = await searchParams;
  const data = await load(orgTree);
  if (!data.ok) {
    const none = /AWSOrganizationsNotInUse/.test(data.error);
    return (
      <Page title="AWS accounts">
        {none ? <Empty icon={ICONS.organizations} action={<ActionForm action={createOrganization} submit="Create an organization" testId="create-organization" />} /> : <ErrorNotice error={data.error} />}
      </Page>
    );
  }
  const { org, tree } = data.value;
  const all = flatten(tree).map((x) => x.node);
  if (tab === "policies") {
    return (
      <Page
        title="Service control policies"
        actions={
          <Sheet title="Create policy" label="Create policy" testId="create-scp">
            <ActionForm action={createPolicy} submit="Create policy" testId="create-scp">
              <Field label="Name">
                <input name="name" required autoFocus />
              </Field>
              <Field label="Description">
                <input name="description" />
              </Field>
              <textarea name="content" rows={12} aria-label="Policy" className="code-editor" defaultValue={DENY_REGIONS} />
            </ActionForm>
          </Sheet>
        }
      >
        <Policies targets={all} />
      </Page>
    );
  }
  return (
    <Page
      title="AWS accounts"
      subtitle={org.Id}
      actions={
        <>
          <Sheet title="Create organizational unit" label="Create organizational unit" icon={<FolderPlus size={16} />} testId="create-ou">
            <ActionForm action={createOu} submit="Create" testId="create-ou">
              <Field label="Name">
                <input name="name" required autoFocus />
              </Field>
              <Field label="Parent">
                <select name="parent">
                  {all.map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.name}
                    </option>
                  ))}
                </select>
              </Field>
            </ActionForm>
          </Sheet>
          <Sheet title="Add an AWS account" label="Add an AWS account" testId="create-account">
            <ActionForm action={createAccount} submit="Create AWS account" testId="create-account">
              <Field label="Account name">
                <input name="name" required autoFocus />
              </Field>
              <Field label="Email address of the account's owner">
                <input name="email" type="email" required />
              </Field>
            </ActionForm>
          </Sheet>
        </>
      }
    >
      <Section>
        <ul className="tree root" aria-label="Organization structure">
          <Tree node={tree} all={all} management={org.MasterAccountId} />
        </ul>
      </Section>
    </Page>
  );
}

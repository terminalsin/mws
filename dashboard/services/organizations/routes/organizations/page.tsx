import { type Account, type PolicyType } from "@aws-sdk/client-organizations";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Status, type Rule } from "@mws-dashboard/ui";
import { CreateAccount, CreateOrganizationalUnit, CreatePolicy } from "@mws-dashboard/ui/model/organizations";
import { ArrowRightLeft, Ban, FolderPlus, Mail, Pencil, Plug, Power, Shield, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { ICONS, organizations } from "../../lib/clients";
import { POLICY_TYPES, example, flatten, orgTree, policiesOfType, policyLimit, targetsForPolicy, type OrgNode } from "../../lib/organizations";
import { createAccount, createOrganization, createOu, createPolicy, deleteOu, disablePolicyType, enablePolicyType, moveAccount, renameOu } from "./actions";

export const metadata: Metadata = { title: "Organizations" };

type Props = {
  searchParams: Promise<{ tab?: string; type?: string; account?: string }>;
};

const STATE_TONE: Record<string, "warn" | "bad"> = {
  PENDING_CLOSURE: "warn",
  SUSPENDED: "warn",
  CLOSED: "bad",
  PENDING_ACTIVATION: "warn",
};

function Tree({ node, all, management }: { node: OrgNode; all: OrgNode[]; management: string | undefined }) {
  const accountRow = (a: Account) => {
    const state = a.State ?? a.Status;
    return (
      <li key={a.Id} className="tree-row">
        <AwsIcon icon={a.Id === management ? ICONS.management : ICONS.account} size={20} />
        <Link className="tree-name" href={`/organizations/accounts/${a.Id}`}>
          {a.Name}
        </Link>
        <code className="muted">{a.Id}</code>
        {a.Id === management && <Pill tone="info">Management</Pill>}
        {state && state !== "ACTIVE" && <Status tone={STATE_TONE[state] ?? "warn"}>{state.toLowerCase().replace(/_/g, " ")}</Status>}
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
  };
  return (
    <li className="tree-node">
      <div className="tree-row">
        <AwsIcon icon={node.kind === "root" ? ICONS.organizations : ICONS.ou} size={20} />
        <span className="tree-name">{node.name}</span>
        <code className="muted">{node.id}</code>
        {node.policies.map((p) => (
          <Link key={p.Id} href={`/organizations/policy?id=${p.Id}`}>
            <Pill icon={<Shield size={11} />} tone={p.AwsManaged ? "neutral" : "info"}>
              {p.Name}
            </Pill>
          </Link>
        ))}
        {node.kind === "ou" && (
          <Sheet title={`Rename ${node.name}`} label={`Rename ${node.name}`} icon={<Pencil size={14} />} testId={`rename-${node.id}`}>
            <ActionForm action={renameOu.bind(null, node.id)} submit="Rename" testId={`rename-${node.id}`}>
              <Field label="Name" rule={CreateOrganizationalUnit.Name}>
                <input name="name" required defaultValue={node.name} />
              </Field>
            </ActionForm>
          </Sheet>
        )}
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

async function policiesWithTargets(type: PolicyType) {
  const client = await organizations();
  const list = await policiesOfType(client, type);
  return Promise.all(
    list.map(async (p) => ({
      p,
      targets: await targetsForPolicy(client, p.Id!),
    })),
  );
}

export default async function Organization({ searchParams }: Props) {
  const { tab = "accounts", type: typeParam, account } = await searchParams;
  if (account) redirect(`/organizations/accounts/${account}`);
  const data = await load(orgTree);
  if (!data.ok) {
    const none = /AWSOrganizationsNotInUse/.test(data.error);
    return (
      <Page title="AWS accounts">
        {none ? (
          <Empty icon={ICONS.organizations} action={<ActionForm action={createOrganization} submit="Create an organization" testId="create-organization" />} />
        ) : (
          <ErrorNotice error={data.error} />
        )}
      </Page>
    );
  }
  const { org, root, tree } = data.value;
  const all = flatten(tree).map((x) => x.node);
  const emails = all.flatMap((n) => n.accounts.map((a) => a.Email!)).filter(Boolean);
  const links = (
    <>
      <Link className="icon-button plain" href="/organizations/invitations" aria-label="Invitations" title="Invitations">
        <Mail size={16} aria-hidden />
      </Link>
      <Link className="icon-button plain" href="/organizations/services" aria-label="Services" title="Services">
        <Plug size={16} aria-hidden />
      </Link>
    </>
  );

  if (tab === "policies") {
    const kind = POLICY_TYPES.find((t) => t.type === typeParam) ?? POLICY_TYPES[0];
    const enabled = root.PolicyTypes?.find((p) => p.Type === kind.type)?.Status;
    const policies = enabled === "ENABLED" ? await load(() => policiesWithTargets(kind.type)) : null;
    const names = policies?.ok ? policies.value.map(({ p }) => p.Name!) : [];
    const content: Rule = {
      ...CreatePolicy.Content,
      format: "json",
      maxLength: policyLimit(kind.type),
    };
    return (
      <Page
        title={kind.label}
        actions={
          <>
            {links}
            {enabled === "ENABLED" && (
              <ActionForm
                action={disablePolicyType.bind(null, root.Id!, kind.type)}
                submit={`Disable ${kind.label.toLowerCase()}`}
                icon={<Ban size={16} />}
                tone="danger"
                confirm={`Disable ${kind.label.toLowerCase()}? Every one of them is detached.`}
                testId="disable-policy-type"
              />
            )}
            <Sheet title="Create policy" label="Create policy" testId="create-scp">
              <ActionForm action={createPolicy} submit="Create policy" testId="create-scp">
                <input type="hidden" name="type" value={kind.type} />
                <Field label="Name" rule={CreatePolicy.Name} taken={names} generate="name" unique>
                  <input name="name" required autoFocus />
                </Field>
                <Field label="Description" rule={{ ...CreatePolicy.Description, required: false }}>
                  <input name="description" />
                </Field>
                <Field label="Policy" rule={content}>
                  <textarea name="content" rows={12} className="code-editor" defaultValue={example(kind.type)} />
                </Field>
              </ActionForm>
            </Sheet>
          </>
        }
      >
        <Segments
          label="Policy types"
          items={POLICY_TYPES.map((t) => ({
            label: t.short,
            href: `/organizations?tab=policies&type=${t.type}`,
            active: t.type === kind.type,
          }))}
        />
        {enabled !== "ENABLED" ? (
          <Empty
            icon={ICONS.policy}
            action={<ActionForm action={enablePolicyType.bind(null, root.Id!, kind.type)} submit={`Enable ${kind.label.toLowerCase()}`} icon={<Power size={16} />} testId="enable-policy-type" />}
          >
            {enabled === "PENDING_ENABLE" ? "Enabling…" : enabled === "PENDING_DISABLE" ? "Disabling…" : "Not enabled"}
          </Empty>
        ) : policies && !policies.ok ? (
          <ErrorNotice error={policies.error} />
        ) : (
          <List
            label={kind.label}
            empty={<Empty icon={ICONS.policy} />}
            rows={(policies?.ok ? policies.value : []).map(({ p, targets }) => ({
              key: p.Id!,
              icon: <AwsIcon icon={ICONS.policy} size={22} />,
              title: p.Name,
              subtitle: p.Description || undefined,
              href: `/organizations/policy?id=${p.Id}`,
              meta: (
                <>
                  {p.AwsManaged && <Pill>AWS managed</Pill>}
                  {targets.length > 0 ? (
                    targets.slice(0, 4).map((t) => (
                      <Pill key={t.TargetId} tone="info">
                        {t.Name}
                      </Pill>
                    ))
                  ) : (
                    <Pill tone="warn">unattached</Pill>
                  )}
                  {targets.length > 4 && <Pill>+{targets.length - 4}</Pill>}
                </>
              ),
            }))}
          />
        )}
      </Page>
    );
  }

  return (
    <Page
      title="AWS accounts"
      subtitle={org.Id}
      actions={
        <>
          {links}
          <Sheet title="Create organizational unit" label="Create organizational unit" icon={<FolderPlus size={16} />} testId="create-ou">
            <ActionForm action={createOu} submit="Create" testId="create-ou">
              <Field label="Name" rule={CreateOrganizationalUnit.Name} generate="name" unique>
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
              <Field label="Account name" rule={CreateAccount.AccountName} generate="name">
                <input name="name" required autoFocus />
              </Field>
              <Field label="Email address of the account's owner" rule={CreateAccount.Email} format="email" taken={emails} unique>
                <input name="email" type="email" required />
              </Field>
            </ActionForm>
          </Sheet>
        </>
      }
    >
      <Facts
        items={[
          ["Feature set", org.FeatureSet === "ALL" ? "All features" : "Consolidated billing"],
          [
            "Management account",
            <Link key="m" href={`/organizations/accounts/${org.MasterAccountId}`}>
              {org.MasterAccountEmail ?? org.MasterAccountId}
            </Link>,
          ],
          ["Accounts", all.reduce((n, x) => n + x.accounts.length, 0)],
        ]}
      />
      <Section>
        <ul className="tree root" aria-label="Organization structure">
          <Tree node={tree} all={all} management={org.MasterAccountId} />
        </ul>
      </Section>
    </Page>
  );
}

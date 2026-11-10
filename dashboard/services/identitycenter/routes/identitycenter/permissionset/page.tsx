import {
  DescribePermissionSetCommand,
  GetInlinePolicyForPermissionSetCommand,
  GetPermissionsBoundaryForPermissionSetCommand,
  ListCustomerManagedPolicyReferencesInPermissionSetCommand,
  ListManagedPoliciesInPermissionSetCommand,
  ListPermissionSetProvisioningStatusCommand,
  ListTagsForResourceCommand,
  DescribePermissionSetProvisioningStatusCommand,
} from "@aws-sdk/client-sso-admin";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Status, Tags, type Rule } from "@mws-dashboard/ui";
import { AttachManagedPolicyToPermissionSet, AttachCustomerManagedPolicyReferenceToPermissionSet, CreatePermissionSet, PutInlinePolicyToPermissionSet } from "@mws-dashboard/ui/model/sso-admin";
import { Link2, Pencil, Plus, RefreshCw, ShieldCheck, ShieldOff, Tag, Trash2, Unlink } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, ssoAdmin } from "../../../lib/clients";
import { POLICIES } from "../../../lib/policies";
import { accounts as listAccounts, duration, instance as loadInstance, outdated, provisionedAccounts } from "../../../lib/sso";
import {
  attachCustomerPolicy,
  attachManagedPolicy,
  deleteBoundary,
  deleteInlinePolicy,
  deletePermissionSet,
  detachCustomerPolicy,
  detachManagedPolicy,
  provisionPermissionSet,
  putBoundary,
  putInlinePolicy,
  savePermissionSetTags,
  updatePermissionSet,
} from "../actions";
import { PolicyEditor } from "@mws-dashboard/ui/policy";

type Props = { searchParams: Promise<{ arn?: string; tab?: string }> };

export const metadata: Metadata = { title: "Permission set" };

const HOURS: Rule = { type: "number", min: 1, max: 12 };
const EXAMPLE = JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "s3:ListAllMyBuckets", Resource: "*" }] }, null, 2);

/** "PT1H30M" in hours (1.5), for the session duration field. */
function hoursOf(iso: string | undefined) {
  const m = iso?.match(/^PT(?:(\d+)H)?(?:(\d+)M)?/);
  return m ? Number(m[1] ?? 0) + Number(m[2] ?? 0) / 60 : 1;
}

export default async function PermissionSet({ searchParams }: Props) {
  const { arn = "", tab = "permissions" } = await searchParams;
  const back = { href: "/identitycenter?tab=permissionsets", label: "Permission sets" };
  const data = await load(async () => {
    const inst = await loadInstance();
    if (!inst) throw new Error("Identity Center is not enabled in this Region");
    const c = await ssoAdmin();
    const q = { InstanceArn: inst.arn, PermissionSetArn: arn };
    const missing = (e: unknown) => {
      if ((e as { name?: string }).name === "ResourceNotFoundException") return undefined;
      throw e;
    };
    const [set, managed, customer, inline, boundary, tags, accounts, stale, everyAccount, provisioning] = await Promise.all([
      c.send(new DescribePermissionSetCommand(q)).then((r) => r.PermissionSet!),
      all((NextToken) => c.send(new ListManagedPoliciesInPermissionSetCommand({ ...q, NextToken })), (r) => r.AttachedManagedPolicies, (r) => r.NextToken),
      all((NextToken) => c.send(new ListCustomerManagedPolicyReferencesInPermissionSetCommand({ ...q, NextToken })), (r) => r.CustomerManagedPolicyReferences, (r) => r.NextToken),
      c.send(new GetInlinePolicyForPermissionSetCommand(q)).then((r) => r.InlinePolicy || undefined),
      c.send(new GetPermissionsBoundaryForPermissionSetCommand(q)).then((r) => r.PermissionsBoundary, missing),
      all((NextToken) => c.send(new ListTagsForResourceCommand({ InstanceArn: inst.arn, ResourceArn: arn, NextToken })), (r) => r.Tags, (r) => r.NextToken),
      provisionedAccounts(inst.arn, arn),
      outdated(inst.arn, arn),
      listAccounts(inst.owner),
      all((NextToken) => c.send(new ListPermissionSetProvisioningStatusCommand({ InstanceArn: inst.arn, Filter: { Status: "IN_PROGRESS" }, NextToken })), (r) => r.PermissionSetsProvisioningStatus, (r) => r.NextToken),
    ]);
    // Provisioning requests of this set still running (the list does not say which set).
    const running = (
      await Promise.all(
        provisioning.map((p) =>
          c.send(new DescribePermissionSetProvisioningStatusCommand({ InstanceArn: inst.arn, ProvisionPermissionSetRequestId: p.RequestId })).then((r) => r.PermissionSetProvisioningStatus),
        ),
      )
    ).filter((p) => p?.PermissionSetArn === arn);
    return { inst, set, managed, customer, inline, boundary, tags, accounts, stale, everyAccount, running };
  });
  if (!data.ok) {
    return (
      <Page title="Permission set" icon={ICONS.policy} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { inst, set, managed, customer, inline, boundary, tags, accounts, stale, everyAccount, running } = data.value;
  const instance = inst.arn;
  const accountName = new Map(everyAccount.map((a) => [a.Id!, a.Name!]));
  const base = `/identitycenter/permissionset?arn=${encodeURIComponent(arn)}`;
  const tabs = [
    { id: "permissions", label: "Permissions", count: managed.length + customer.length + (inline ? 1 : 0) },
    { id: "accounts", label: "Accounts", count: accounts.length },
    { id: "tags", label: "Tags", count: tags.length || undefined },
  ];
  const active = tabs.find((t) => t.id === tab)?.id ?? "permissions";
  const boundaryName = boundary?.ManagedPolicyArn ?? (boundary?.CustomerManagedPolicyReference ? `${boundary.CustomerManagedPolicyReference.Path ?? "/"}${boundary.CustomerManagedPolicyReference.Name}` : undefined);

  let body;
  if (active === "accounts") {
    body = (
      <Section title="Provisioned to" count={accounts.length} plain>
        <List
          label="Accounts"
          empty={<Empty icon="resource/AWSOrganizationsAccount" />}
          rows={accounts.map((a) => ({
            key: a,
            icon: <AwsIcon icon="resource/AWSOrganizationsAccount" size={22} />,
            title: accountName.get(a) ?? a,
            subtitle: a,
            href: `/identitycenter/accounts/${a}`,
            meta: stale.includes(a) ? <Pill tone="warn">outdated</Pill> : <Pill tone="good">current</Pill>,
          }))}
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
            <ActionForm action={savePermissionSetTags.bind(null, instance, arn, tags.map((t) => t.Key!))} submit="Save" testId="edit-tags">
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
  } else {
    body = (
      <>
        <Section
          title="AWS managed policies"
          count={managed.length}
          plain
          actions={
            <Sheet title="Attach AWS managed policy" label="Attach AWS managed policy" icon={<Link2 size={16} />} testId="attach-managed-policy">
              <ActionForm action={attachManagedPolicy.bind(null, instance, arn)} submit="Attach" testId="attach-managed-policy">
                <Field label="Policy ARN" rule={{ ...AttachManagedPolicyToPermissionSet.ManagedPolicyArn, format: "arn" }} known={POLICIES.filter((p) => !managed.some((m) => m.Arn === p))}>
                  <input name="policy" list="managed-policies" required placeholder="arn:aws:iam::aws:policy/ReadOnlyAccess" />
                </Field>
                <datalist id="managed-policies">
                  {POLICIES.map((p) => (
                    <option key={p} value={p}>
                      {p.split("/").pop()}
                    </option>
                  ))}
                </datalist>
              </ActionForm>
            </Sheet>
          }
        >
          <List
            label="AWS managed policies"
            rows={managed.map((m) => ({
              key: m.Arn!,
              icon: <AwsIcon icon={ICONS.policy} size={22} />,
              title: m.Name,
              subtitle: m.Arn,
              href: `/iam/policy?arn=${encodeURIComponent(m.Arn!)}`,
              actions: <ActionForm action={detachManagedPolicy.bind(null, instance, arn, m.Arn!)} submit={`Detach ${m.Name}`} icon={<Unlink size={15} />} />,
            }))}
          />
        </Section>
        <Section
          title="Customer managed policies"
          count={customer.length}
          plain
          actions={
            <Sheet title="Attach customer managed policy" label="Attach customer managed policy" icon={<Plus size={16} />} testId="attach-customer-policy">
              <ActionForm action={attachCustomerPolicy.bind(null, instance, arn)} submit="Attach" testId="attach-customer-policy">
                <Field label="Policy name" rule={AttachCustomerManagedPolicyReferenceToPermissionSet.CustomerManagedPolicyReference.fields?.Name} hint="Must exist with this name in every account">
                  <input name="name" required />
                </Field>
                <Field label="Path" rule={{ ...AttachCustomerManagedPolicyReferenceToPermissionSet.CustomerManagedPolicyReference.fields?.Path, format: "path" }}>
                  <input name="path" placeholder="/" />
                </Field>
              </ActionForm>
            </Sheet>
          }
        >
          <List
            label="Customer managed policies"
            rows={customer.map((p) => ({
              key: `${p.Path}${p.Name}`,
              icon: <AwsIcon icon={ICONS.policy} size={22} />,
              title: p.Name,
              subtitle: p.Path && p.Path !== "/" ? p.Path : undefined,
              actions: <ActionForm action={detachCustomerPolicy.bind(null, instance, arn, p.Name!, p.Path)} submit={`Detach ${p.Name}`} icon={<Unlink size={15} />} />,
            }))}
          />
        </Section>
        <Section
          title="Inline policy"
          actions={
            <>
              <Sheet title="Inline policy" label={inline ? "Edit inline policy" : "Create inline policy"} icon={<Pencil size={16} />} testId="inline-policy">
                <ActionForm action={putInlinePolicy.bind(null, instance, arn)} submit="Save" testId="inline-policy">
                  <PolicyEditor label="Document" rule={{ ...PutInlinePolicyToPermissionSet.InlinePolicy, format: "policy" }} name="document" rows={14} required aria-label="Inline policy" defaultValue={inline ? pretty(inline) : EXAMPLE} />
                </ActionForm>
              </Sheet>
              {inline && <ActionForm action={deleteInlinePolicy.bind(null, instance, arn)} submit="Delete inline policy" icon={<Trash2 size={16} />} tone="danger" confirm="Delete the inline policy?" />}
            </>
          }
        >
          {inline ? <CodeBlock value={inline} label="Inline policy" /> : <Empty>—</Empty>}
        </Section>
        <Section
          title="Permissions boundary"
          plain
          actions={
            <Sheet title="Permissions boundary" label={boundary ? "Change boundary" : "Set boundary"} icon={<ShieldCheck size={16} />} testId="set-boundary">
              <ActionForm action={putBoundary.bind(null, instance, arn)} submit="Set" testId="set-boundary">
                <Field label="AWS managed policy ARN, or customer managed policy name" hint="A name may carry its path: /team/Boundary" known={POLICIES}>
                  <input name="policy" required defaultValue={boundaryName} />
                </Field>
              </ActionForm>
            </Sheet>
          }
        >
          {boundaryName && (
            <List
              label="Permissions boundary"
              rows={[
                {
                  key: boundaryName,
                  icon: <ShieldCheck size={18} />,
                  title: boundaryName.split("/").pop(),
                  subtitle: boundary?.ManagedPolicyArn ? "AWS managed" : "Customer managed",
                  actions: <ActionForm action={deleteBoundary.bind(null, instance, arn)} submit="Remove boundary" icon={<ShieldOff size={15} />} tone="danger" confirm="Remove the permissions boundary?" />,
                },
              ]}
            />
          )}
        </Section>
      </>
    );
  }

  return (
    <Page
      title={set.Name}
      icon={ICONS.policy}
      back={back}
      subtitle={arn}
      actions={
        <>
          {accounts.length > 0 && (
            <ActionForm action={provisionPermissionSet.bind(null, instance, arn)} submit="Update in all provisioned accounts" icon={<RefreshCw size={16} />} tone={stale.length ? "primary" : "plain"} testId="provision" />
          )}
          <Sheet title={`Edit ${set.Name}`} label="Edit details" icon={<Pencil size={16} />} testId="edit-permission-set">
            <ActionForm action={updatePermissionSet.bind(null, instance, arn)} submit="Save" testId="edit-permission-set">
              <Field label="Description" rule={CreatePermissionSet.Description}>
                <input name="description" defaultValue={set.Description} />
              </Field>
              <Field label="Session duration (hours)" rule={HOURS}>
                <input name="hours" type="number" min={1} max={12} step="any" defaultValue={hoursOf(set.SessionDuration)} />
              </Field>
              <Field label="Relay state" rule={CreatePermissionSet.RelayState} format="url">
                <input name="relay" defaultValue={set.RelayState} placeholder="https://console.aws.amazon.com/s3" />
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm
            action={deletePermissionSet.bind(null, instance, arn, true)}
            submit="Delete permission set"
            icon={<Trash2 size={16} />}
            tone="danger"
            confirm={`Delete ${set.Name}?`}
            testId="delete-permission-set"
          />
        </>
      }
    >
      <Facts
        items={[
          running.length > 0 && ["Provisioning", <Status key="p" tone="info">in progress</Status>],
          stale.length > 0 && [
            "Needs provisioning",
            <Link key="s" href={`${base}&tab=accounts`}>
              <Pill tone="warn" icon={<RefreshCw size={11} />}>
                {stale.length} {stale.length === 1 ? "account" : "accounts"}
              </Pill>
            </Link>,
          ],
          set.Description && ["Description", set.Description],
          ["Session duration", duration(set.SessionDuration)],
          set.RelayState && ["Relay state", set.RelayState],
          ["Created", ago(set.CreatedDate)],
        ]}
      />
      <Segments label="Permission set tabs" items={tabs.map((t) => ({ label: t.label, href: t.id === "permissions" ? base : `${base}&tab=${t.id}`, active: active === t.id, count: t.count }))} />
      {body}
    </Page>
  );
}

function pretty(doc: string) {
  try {
    return JSON.stringify(JSON.parse(doc), null, 2);
  } catch {
    return doc;
  }
}

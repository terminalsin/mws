import { GetResourceShareInvitationsCommand, GetResourceSharesCommand, ListPendingInvitationResourcesCommand, ListPermissionsCommand, ListResourceTypesCommand } from "@aws-sdk/client-ram";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Section, Segments, Sheet, Status, type Rule } from "@mws-dashboard/ui";
import { CreatePermission, CreateResourceShare } from "@mws-dashboard/ui/model/ram";
import { Building2, Check, Globe, X } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, orgSharing, permissionHref, ram, shareHref, shareTargets } from "../../lib/clients";
import { shareRules } from "../../lib/rules";
import { answerInvitation, createPermission, createShare, enableOrgSharing } from "./actions";

export const metadata: Metadata = { title: "RAM" };

type Props = { searchParams: Promise<{ tab?: string }> };

const NAME: Rule = { ...CreateResourceShare.name, generate: "name" };

const STATUS_TONE: Record<string, "good" | "warn" | "bad" | "neutral"> = { ACTIVE: "good", PENDING: "warn", FAILED: "bad", DELETING: "warn", ACCEPTED: "good", REJECTED: "neutral", EXPIRED: "neutral" };
const TABS = [
  { id: "mine", label: "Shared by me", href: "/ram" },
  { id: "others", label: "Shared with me", href: "/ram?tab=others" },
  { id: "permissions", label: "Managed permissions", href: "/ram?tab=permissions" },
];
// Invitations expire after seven days.
const EXPIRY_MS = 7 * 24 * 3600 * 1000;

async function allPermissions() {
  const client = await ram();
  return all(
    (nextToken) => client.send(new ListPermissionsCommand({ nextToken })),
    (r) => r.permissions,
    (r) => r.nextToken,
  );
}

async function Permissions() {
  const [perms, types] = await Promise.all([
    load(allPermissions),
    load(async () => (await (await ram()).send(new ListResourceTypesCommand({}))).resourceTypes ?? []),
  ]);
  const create = (
    <Sheet title="Create customer managed permission" label="Create permission" testId="create-permission">
      <ActionForm action={createPermission} submit="Create" testId="create-permission">
        <Field label="Name" rule={{ ...CreatePermission.name, generate: "name" }} unique>
          <input name="name" required />
        </Field>
        <Field label="Resource type" rule={CreatePermission.resourceType}>
          <select name="resourceType">
            {(types.ok ? types.value : []).map((t) => (
              <option key={t.resourceType} value={t.resourceType}>
                {t.resourceType}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Policy template" rule={CreatePermission.policyTemplate} format="json" member="policyTemplate">
          <textarea name="policy" rows={8} className="code-editor" defaultValue={JSON.stringify({ Effect: "Allow", Action: ["acm-pca:IssueCertificate", "acm-pca:GetCertificate"] }, null, 2)} />
        </Field>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="Managed permissions" actions={create}>
      <Segments label="RAM" items={TABS.map((t) => ({ label: t.label, href: t.href, active: t.id === "permissions" }))} />
      {perms.ok ? (
        <>
          {(["CUSTOMER_MANAGED", "AWS_MANAGED"] as const).map((kind) => {
            const list = perms.value.filter((p) => (p.permissionType ?? "AWS_MANAGED") === kind);
            if (!list.length) return null;
            return (
              <Section key={kind} title={kind === "AWS_MANAGED" ? "AWS managed" : "Customer managed"} count={list.length} plain>
                <List
                  label={`${kind} permissions`}
                  rows={list.map((p) => ({
                    key: p.arn!,
                    icon: <AwsIcon icon={ICONS.ram} size={22} />,
                    title: p.name,
                    subtitle: p.resourceType,
                    href: permissionHref(p.arn),
                    meta: (
                      <>
                        {p.isResourceTypeDefault && <Pill tone="info">Default</Pill>}
                        <span>v{p.version}</span>
                        {p.status && p.status !== "ATTACHABLE" && <Status tone="warn">{p.status.toLowerCase()}</Status>}
                      </>
                    ),
                  }))}
                />
              </Section>
            );
          })}
        </>
      ) : (
        <ErrorNotice error={perms.error} />
      )}
    </Page>
  );
}

async function Invitations() {
  const invitations = await load(async () => {
    const client = await ram();
    const list = await all(
      (nextToken) => client.send(new GetResourceShareInvitationsCommand({ nextToken })),
      (r) => r.resourceShareInvitations,
      (r) => r.nextToken,
    );
    const pending = list.filter((i) => i.status === "PENDING");
    const resources = await Promise.all(
      pending.map((i) => client.send(new ListPendingInvitationResourcesCommand({ resourceShareInvitationArn: i.resourceShareInvitationArn })).then((r) => r.resources ?? [], () => [])),
    );
    return { list, pending: pending.map((i, n) => ({ i, resources: resources[n] })) };
  });
  if (!invitations.ok) return <ErrorNotice error={invitations.error} />;
  const { list, pending } = invitations.value;
  const past = list.filter((i) => i.status !== "PENDING");
  return (
    <>
      {pending.length > 0 && (
        <Section title="Pending invitations" count={pending.length} plain>
          <List
            label="Invitations"
            rows={pending.map(({ i, resources }) => {
              const expires = i.invitationTimestamp ? new Date(i.invitationTimestamp.getTime() + EXPIRY_MS) : undefined;
              return {
                key: i.resourceShareInvitationArn!,
                icon: <AwsIcon icon={ICONS.ram} size={22} />,
                title: i.resourceShareName,
                subtitle: [`from ${i.senderAccountId}`, ...resources.map((r) => `${r.type}: ${r.arn?.split(/[:/]/).pop()}`)].join(" · "),
                meta: <span title={expires?.toISOString()}>expires {ago(expires)}</span>,
                actions: (
                  <>
                    <ActionForm action={answerInvitation.bind(null, i.resourceShareInvitationArn!, true)} submit={`Accept ${i.resourceShareName}`} icon={<Check size={15} />} />
                    <ActionForm action={answerInvitation.bind(null, i.resourceShareInvitationArn!, false)} submit={`Reject ${i.resourceShareName}`} icon={<X size={15} />} tone="danger" />
                  </>
                ),
              };
            })}
          />
        </Section>
      )}
      {past.length > 0 && (
        <Section title="Past invitations" count={past.length} plain>
          <List
            label="Past invitations"
            rows={past.map((i) => ({
              key: i.resourceShareInvitationArn!,
              icon: <AwsIcon icon={ICONS.ram} size={22} />,
              title: i.resourceShareName,
              subtitle: `from ${i.senderAccountId}`,
              href: i.status === "ACCEPTED" ? shareHref(i.resourceShareArn) : undefined,
              meta: (
                <>
                  <Status tone={STATUS_TONE[i.status ?? ""] ?? "neutral"}>{i.status?.toLowerCase()}</Status>
                  <span>{ago(i.invitationTimestamp)}</span>
                </>
              ),
            }))}
          />
        </Section>
      )}
    </>
  );
}

export default async function Shares({ searchParams }: Props) {
  const { tab = "mine" } = await searchParams;
  if (tab === "permissions") return <Permissions />;
  const client = await ram();
  const owner = tab === "others" ? "OTHER-ACCOUNTS" : "SELF";
  const [shares, targets, org, perms] = await Promise.all([
    load(async () =>
      (
        await all(
          (nextToken) => client.send(new GetResourceSharesCommand({ resourceOwner: owner, nextToken })),
          (r) => r.resourceShares,
          (r) => r.nextToken,
        )
      ).filter((s) => s.status !== "DELETED"),
    ),
    tab === "others" ? null : shareTargets(),
    tab === "others" ? null : orgSharing(),
    tab === "others" ? null : allPermissions().catch(() => []),
  ]);
  const RULES = shareRules(targets);
  const create = (
    <Sheet title="Create resource share" label="Create resource share" testId="create-share">
      <ActionForm action={createShare} submit="Create resource share" testId="create-share">
        <Field label="Name" rule={NAME}>
          <input name="name" required autoFocus />
        </Field>
        <Field label="Resource ARNs" rule={RULES.resources} member="resourceArns">
          <textarea name="resources" rows={3} placeholder="arn:aws:acm-pca:…:certificate-authority/…" />
        </Field>
        <Field label="Principals" rule={RULES.principals} member="principals">
          <textarea name="principals" rows={2} placeholder="111122223333 or an OU / organization ARN" />
        </Field>
        {perms && perms.length > 0 && (
          <Field label="Managed permission" member="permissionArns">
            <select name="permission" defaultValue="">
              <option value="">Default for each resource type</option>
              {perms.map((p) => (
                <option key={p.arn} value={p.arn}>
                  {p.name} · {p.resourceType}
                </option>
              ))}
            </select>
          </Field>
        )}
        <label className="check">
          <input type="checkbox" name="external" /> Allow sharing outside the organization
        </label>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title={tab === "others" ? "Shared with me" : "Shared by me"} actions={tab === "others" ? undefined : create}>
      <Segments label="RAM" items={TABS.map((t) => ({ label: t.label, href: t.href, active: t.id === tab }))} />
      {org && org.state !== "none" && (
        <div className="banner" role="status">
          <Building2 size={15} aria-hidden />
          {org.state === "on" ? (
            <span>Sharing with your organization is on: accounts in it need no invitation.</span>
          ) : (
            <>
              <span>Sharing with your organization is off: every account gets an invitation.</span>
              {org.management && <ActionForm action={enableOrgSharing} submit="Enable sharing with AWS Organizations" inline testId="enable-org-sharing" />}
            </>
          )}
        </div>
      )}
      {tab === "others" && <Invitations />}
      {shares.ok ? (
        <List
          label="Resource shares"
          empty={<Empty icon={ICONS.ram} action={tab === "others" ? undefined : create} />}
          rows={shares.value.map((s) => ({
            key: s.resourceShareArn!,
            icon: <AwsIcon icon={ICONS.ram} size={22} />,
            title: s.name,
            subtitle: tab === "others" ? `from ${s.owningAccountId}` : s.statusMessage,
            href: shareHref(s.resourceShareArn),
            meta: (
              <>
                {s.allowExternalPrincipals && <Globe size={13} aria-label="External principals allowed" />}
                {s.featureSet && s.featureSet !== "STANDARD" && <Pill>{s.featureSet.toLowerCase()}</Pill>}
                <Status tone={STATUS_TONE[s.status ?? ""] ?? "warn"}>{s.status?.toLowerCase()}</Status>
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


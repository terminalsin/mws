import {
  GetGroupCommand,
  GetRoleCommand,
  GetUserCommand,
  ListAccessKeysCommand,
  ListAttachedGroupPoliciesCommand,
  ListAttachedRolePoliciesCommand,
  ListAttachedUserPoliciesCommand,
  ListGroupsCommand,
  ListGroupsForUserCommand,
  ListPoliciesCommand,
  ListRolePoliciesCommand,
  ListUserPoliciesCommand,
  type AttachedPolicy,
} from "@aws-sdk/client-iam";
import { ago, frameInfo, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Sheet, Status, Tags } from "@mws-dashboard/ui";
import { KeyRound, Pencil, Play, Pause, Trash2, Unlink, UserMinus, UserPlus, Link2 } from "lucide-react";

import { ICONS, iam, policyDocument, principalIcon, trust } from "../../lib/clients";
import {
  addToGroup,
  attachPolicy,
  createAccessKey,
  deleteAccessKey,
  deleteInlinePolicy,
  deletePrincipal,
  detachPolicy,
  putInlinePolicy,
  removeFromGroup,
  setAccessKey,
  updateTrust,
  type Kind,
} from "./actions";

const EXAMPLE = JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "s3:ListBucket", Resource: "*" }] }, null, 2);

async function details(kind: Kind, name: string) {
  const client = await iam();
  const policies = client.send(new ListPoliciesCommand({ MaxItems: 1000, OnlyAttached: false })).then((r) => r.Policies ?? []);
  if (kind === "role") {
    const [role, attached, inline, all] = await Promise.all([
      client.send(new GetRoleCommand({ RoleName: name })),
      client.send(new ListAttachedRolePoliciesCommand({ RoleName: name })),
      client.send(new ListRolePoliciesCommand({ RoleName: name })),
      policies,
    ]);
    const r = role.Role!;
    return {
      arn: r.Arn!,
      created: r.CreateDate,
      lastUsed: r.RoleLastUsed?.LastUsedDate,
      trust: policyDocument(r.AssumeRolePolicyDocument),
      maxSession: r.MaxSessionDuration,
      tags: r.Tags,
      attached: attached.AttachedPolicies ?? [],
      inline: inline.PolicyNames ?? [],
      all,
    };
  }
  if (kind === "user") {
    const [user, attached, inline, keys, groups, allGroups, all] = await Promise.all([
      client.send(new GetUserCommand({ UserName: name })),
      client.send(new ListAttachedUserPoliciesCommand({ UserName: name })),
      client.send(new ListUserPoliciesCommand({ UserName: name })),
      client.send(new ListAccessKeysCommand({ UserName: name })),
      client.send(new ListGroupsForUserCommand({ UserName: name })),
      client.send(new ListGroupsCommand({})),
      policies,
    ]);
    const u = user.User!;
    return {
      arn: u.Arn!,
      created: u.CreateDate,
      lastUsed: u.PasswordLastUsed,
      tags: u.Tags,
      attached: attached.AttachedPolicies ?? [],
      inline: inline.PolicyNames ?? [],
      keys: keys.AccessKeyMetadata ?? [],
      groups: groups.Groups ?? [],
      allGroups: allGroups.Groups ?? [],
      all,
    };
  }
  const [group, attached, all] = await Promise.all([
    client.send(new GetGroupCommand({ GroupName: name })),
    client.send(new ListAttachedGroupPoliciesCommand({ GroupName: name })),
    policies,
  ]);
  return {
    arn: group.Group!.Arn!,
    created: group.Group!.CreateDate,
    members: group.Users ?? [],
    attached: attached.AttachedPolicies ?? [],
    all,
  };
}

const ICON: Record<Kind, string> = { role: ICONS.role, user: ICONS.user, group: ICONS.users };
const BACK: Record<Kind, string> = { role: "/iam?tab=roles", user: "/iam", group: "/iam?tab=groups" };

/** The detail page of a role, user or group: who may use it and what it may do. */
export async function Principal({ kind, name }: { kind: Kind; name: string }) {
  const [data, info] = await Promise.all([load(() => details(kind, name)), frameInfo()]);
  const back = { href: BACK[kind], label: { role: "Roles", user: "Users", group: "Groups" }[kind] };
  if (!data.ok) {
    return (
      <Page title={name} icon={ICON[kind]} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const d = data.value;
  const attachedArns = new Set(d.attached.map((p) => p.PolicyArn));
  const attachable = d.all.filter((p) => !attachedArns.has(p.Arn));
  const who = "trust" in d && d.trust ? trust(d.trust, info.account) : null;

  const policyRow = (p: AttachedPolicy) => ({
    key: p.PolicyArn!,
    icon: <AwsIcon icon={ICONS.policy} size={22} />,
    title: p.PolicyName,
    subtitle: p.PolicyArn!.includes(":aws:policy/") ? "AWS managed" : undefined,
    href: `/iam/policy?arn=${encodeURIComponent(p.PolicyArn!)}`,
    actions: <ActionForm action={detachPolicy.bind(null, kind, name, p.PolicyArn!)} submit={`Detach ${p.PolicyName}`} icon={<Unlink size={15} />} />,
  });

  return (
    <Page
      title={name}
      icon={ICON[kind]}
      back={back}
      subtitle={d.arn}
      actions={
        <ActionForm
          action={deletePrincipal.bind(null, kind, name)}
          submit={`Delete ${kind}`}
          icon={<Trash2 size={16} />}
          tone="danger"
          confirm={`Delete ${name}?`}
          testId={`delete-${kind}`}
        />
      }
    >
      <Facts
        items={[
          who && [
            "Trusted by",
            who.services.length ? (
              <span className="icon-stack">
                {who.services.map((s) => (
                  <span key={s} title={s}>
                    <AwsIcon icon={principalIcon(s)} size={20} label={s} />
                  </span>
                ))}
              </span>
            ) : (
              <Pill tone={who.kind === "cross-account" ? "warn" : "neutral"}>{who.kind}</Pill>
            ),
          ],
          ["lastUsed" in d && d.lastUsed ? "Last used" : "Created", ago(("lastUsed" in d && d.lastUsed) || d.created)],
          "maxSession" in d && d.maxSession && d.maxSession !== 3600 && ["Max session", `${d.maxSession / 3600} h`],
          "tags" in d && d.tags?.length && ["Tags", <Tags key="t" tags={d.tags} />],
        ]}
      />

      {d.keys && (
        <Section
          title="Access keys"
          count={d.keys.length}
          plain
          actions={
            d.keys.length < 2 && (
              <Sheet title="New access key" label="Create access key" icon={<KeyRound size={16} />} testId="create-access-key">
                <ActionForm action={createAccessKey.bind(null, name)} submit="Create" testId="create-access-key" />
              </Sheet>
            )
          }
        >
          <List
            label="Access keys"
            empty={<Empty>—</Empty>}
            rows={d.keys.map((k) => {
              const active = k.Status === "Active";
              return {
                key: k.AccessKeyId!,
                icon: <KeyRound size={18} />,
                title: <code>{k.AccessKeyId}</code>,
                meta: <Status tone={active ? "good" : "neutral"}>{ago(k.CreateDate)}</Status>,
                actions: (
                  <>
                    <ActionForm
                      action={setAccessKey.bind(null, name, k.AccessKeyId!, !active)}
                      submit={active ? `Deactivate ${k.AccessKeyId}` : `Activate ${k.AccessKeyId}`}
                      icon={active ? <Pause size={15} /> : <Play size={15} />}
                    />
                    <ActionForm
                      action={deleteAccessKey.bind(null, name, k.AccessKeyId!)}
                      submit={`Delete ${k.AccessKeyId}`}
                      icon={<Trash2 size={15} />}
                      tone="danger"
                      confirm={`Delete ${k.AccessKeyId}?`}
                    />
                  </>
                ),
              };
            })}
          />
        </Section>
      )}

      <Section
        title="Permissions"
        count={d.attached.length + (d.inline?.length ?? 0)}
        plain
        actions={
          <>
            <Sheet title="Attach policy" label="Attach policy" icon={<Link2 size={16} />} testId="attach-policy">
              <ActionForm action={attachPolicy.bind(null, kind, name)} submit="Attach" testId="attach-policy">
                <Field label="Policy">
                  <input name="policyArn" list="policies" required placeholder="arn:aws:iam::aws:policy/ReadOnlyAccess" />
                </Field>
                <datalist id="policies">
                  {attachable.map((p) => (
                    <option key={p.Arn} value={p.Arn}>
                      {p.PolicyName}
                    </option>
                  ))}
                </datalist>
              </ActionForm>
            </Sheet>
            {kind !== "group" && (
              <Sheet title="Inline policy" label="Add inline policy" icon={<Pencil size={16} />} testId="inline-policy">
                <ActionForm action={putInlinePolicy.bind(null, kind, name)} submit="Save" testId="inline-policy">
                  <Field label="Name">
                    <input name="policyName" required />
                  </Field>
                  <textarea name="document" rows={12} aria-label="Policy document" defaultValue={EXAMPLE} />
                </ActionForm>
              </Sheet>
            )}
          </>
        }
      >
        <List
          label="Permissions"
          empty={<Empty icon={ICONS.policy} />}
          rows={[
            ...d.attached.map(policyRow),
            ...(d.inline && kind !== "group"
              ? d.inline.map((p) => ({
                  key: `inline:${p}`,
                  icon: <Pencil size={18} />,
                  title: p,
                  subtitle: "Inline",
                  actions: (
                    <ActionForm
                      action={deleteInlinePolicy.bind(null, kind, name, p)}
                      submit={`Delete ${p}`}
                      icon={<Trash2 size={15} />}
                      tone="danger"
                      confirm={`Delete ${p}?`}
                    />
                  ),
                }))
              : []),
          ]}
        />
      </Section>

      {d.groups && d.allGroups && (
        <Section
          title="Groups"
          count={d.groups.length}
          plain
          actions={
            <Sheet title="Add to group" label="Add to group" icon={<UserPlus size={16} />}>
              <ActionForm action={addToGroup.bind(null, name)} submit="Add">
                <Field label="Group">
                  <select name="group" required>
                    {d.allGroups
                      .filter((g) => !d.groups!.some((m) => m.GroupName === g.GroupName))
                      .map((g) => (
                        <option key={g.GroupId}>{g.GroupName}</option>
                      ))}
                  </select>
                </Field>
              </ActionForm>
            </Sheet>
          }
        >
          <List
            label="Groups"
            empty={<Empty>—</Empty>}
            rows={d.groups.map((g) => ({
              key: g.GroupId!,
              icon: <AwsIcon icon={ICONS.users} size={22} />,
              title: g.GroupName,
              href: `/iam/groups/${encodeURIComponent(g.GroupName!)}`,
              actions: (
                <ActionForm action={removeFromGroup.bind(null, name, g.GroupName!)} submit={`Leave ${g.GroupName}`} icon={<UserMinus size={15} />} />
              ),
            }))}
          />
        </Section>
      )}

      {d.members && (
        <Section title="Members" count={d.members.length} plain>
          <List
            label="Members"
            empty={<Empty icon={ICONS.user} />}
            rows={d.members.map((u) => ({
              key: u.UserId!,
              icon: <AwsIcon icon={ICONS.user} size={22} />,
              title: u.UserName,
              href: `/iam/users/${encodeURIComponent(u.UserName!)}`,
            }))}
          />
        </Section>
      )}

      {"trust" in d && (
        <Section
          title="Trust policy"
          actions={
            <Sheet title="Trust policy" label="Edit trust policy" icon={<Pencil size={16} />} testId="edit-trust">
              <ActionForm action={updateTrust.bind(null, name)} submit="Save" testId="edit-trust">
                <textarea name="document" rows={14} aria-label="Trust policy" defaultValue={pretty(d.trust)} />
              </ActionForm>
            </Sheet>
          }
        >
          <CodeBlock value={d.trust} label="Trust policy" />
        </Section>
      )}
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

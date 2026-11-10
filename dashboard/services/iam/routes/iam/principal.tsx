import {
  GetAccessKeyLastUsedCommand,
  GetGroupCommand,
  GetLoginProfileCommand,
  GetRoleCommand,
  GetServiceLinkedRoleDeletionStatusCommand,
  GetUserCommand,
  ListAccessKeysCommand,
  ListMFADevicesCommand,
  ListUsersCommand,
  type AttachedPolicy,
  type IAMClient,
} from "@aws-sdk/client-iam";
import { ago, all, frameInfo, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Status, Tags } from "@mws-dashboard/ui";
import { CreateInstanceProfile, CreateLoginProfile, UpdateRole } from "@mws-dashboard/ui/model/iam";
import { FlaskConical, KeyRound, Link2, LockKeyhole, Pause, Pencil, Play, Plus, ShieldCheck, ShieldOff, Smartphone, Tag, Trash2, Unlink, UserMinus, UserPlus } from "lucide-react";
import Link from "next/link";

import { ICONS, iam, policyDocument, principalIcon, trust } from "../../lib/clients";
import { allGroups, attachedPolicies, groupMembers, groupsForUser, inlinePolicies, instanceProfilesForRole, policies, serviceLinked, type Kind } from "../../lib/iam";
import { AttachFields, PolicyFields } from "../../lib/forms.tsx";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";
import { PolicyEditor } from "@mws-dashboard/ui/policy";
import { RULES } from "../../lib/rules";
import {
  addMember,
  addToGroup,
  attachPolicy,
  createAccessKey,
  createInstanceProfile,
  deleteAccessKey,
  deleteBoundary,
  deleteInlinePolicy,
  deleteLoginProfile,
  deletePrincipal,
  deleteServiceLinkedRole,
  detachPolicy,
  putBoundary,
  putInlinePolicy,
  removeFromGroup,
  removeMfa,
  renamePrincipal,
  saveLoginProfile,
  saveTags,
  setAccessKey,
  updateRole,
  updateTrust,
} from "./actions";

const missing = (e: unknown) => (e as { name?: string }).name === "NoSuchEntityException";

async function role(client: IAMClient, name: string) {
  const [out, attached, inline, profiles, all] = await Promise.all([
    client.send(new GetRoleCommand({ RoleName: name })),
    attachedPolicies(client, "role", name),
    inlinePolicies(client, "role", name),
    instanceProfilesForRole(client, name),
    policies(client),
  ]);
  return { kind: "role" as const, role: out.Role!, attached, inline, profiles, all };
}

async function user(client: IAMClient, name: string) {
  const [out, attached, inline, keys, groups, everyGroup, login, mfa, all] = await Promise.all([
    client.send(new GetUserCommand({ UserName: name })),
    attachedPolicies(client, "user", name),
    inlinePolicies(client, "user", name),
    client.send(new ListAccessKeysCommand({ UserName: name })).then((r) => r.AccessKeyMetadata ?? []),
    groupsForUser(client, name),
    allGroups(client),
    client.send(new GetLoginProfileCommand({ UserName: name })).then(
      (r) => r.LoginProfile ?? null,
      (e) => {
        if (missing(e)) return null;
        throw e;
      },
    ),
    client.send(new ListMFADevicesCommand({ UserName: name })).then((r) => r.MFADevices ?? []),
    policies(client),
  ]);
  const used = await Promise.all(
    keys.map((k) => client.send(new GetAccessKeyLastUsedCommand({ AccessKeyId: k.AccessKeyId })).then((r) => r.AccessKeyLastUsed, () => undefined)),
  );
  return { kind: "user" as const, user: out.User!, attached, inline, keys: keys.map((k, i) => ({ ...k, used: used[i] })), groups, everyGroup, login, mfa, all };
}

async function group(client: IAMClient, name: string) {
  const [out, members, attached, inline, users, everyPolicy] = await Promise.all([
    client.send(new GetGroupCommand({ GroupName: name })),
    groupMembers(client, name),
    attachedPolicies(client, "group", name),
    inlinePolicies(client, "group", name),
    all((Marker) => client.send(new ListUsersCommand({ Marker })), (r) => r.Users, (r) => (r.IsTruncated ? r.Marker : undefined)),
    policies(client),
  ]);
  return { kind: "group" as const, group: out.Group!, members, attached, inline, users, all: everyPolicy };
}

async function details(kind: Kind, name: string) {
  const client = await iam();
  if (kind === "role") return role(client, name);
  if (kind === "user") return user(client, name);
  return group(client, name);
}

const ICON: Record<Kind, string> = { role: ICONS.role, user: ICONS.user, group: ICONS.users };
const BACK: Record<Kind, string> = { role: "/iam?tab=roles", user: "/iam", group: "/iam?tab=groups" };
const DELETION_TONE: Record<string, "good" | "bad" | "info"> = { SUCCEEDED: "good", FAILED: "bad", IN_PROGRESS: "info", NOT_STARTED: "info" };

/** A service-linked role being deleted: the task's status, refreshed until done. */
async function Deletion({ name, task, back }: { name: string; task: string; back: { href: string; label: string } }) {
  const status = await load(async () => (await iam()).send(new GetServiceLinkedRoleDeletionStatusCommand({ DeletionTaskId: task })));
  return (
    <Page title={name} icon={ICONS.role} back={back}>
      {status.ok ? (
        <Facts
          items={[
            ["Deletion", <Status key="s" tone={DELETION_TONE[status.value.Status!] ?? "neutral"}>{status.value.Status === "IN_PROGRESS" ? "in progress" : status.value.Status!.toLowerCase().replace(/_/g, " ")}</Status>],
            status.value.Reason?.Reason && ["Reason", status.value.Reason.Reason],
            ...(status.value.Reason?.RoleUsageList ?? []).map((u) => [u.Region, (u.Resources ?? []).join(", ")] as [string, string]),
          ]}
        />
      ) : (
        <ErrorNotice error={status.error} />
      )}
    </Page>
  );
}

/** The detail page of a role, user or group, with AWS's tabs. */
export async function Principal({ kind, name, tab, deletion }: { kind: Kind; name: string; tab?: string; deletion?: string }) {
  const back = { href: BACK[kind], label: { role: "Roles", user: "Users", group: "Groups" }[kind] };
  const [data, info] = await Promise.all([load(() => details(kind, name)), frameInfo()]);
  if (deletion && (!data.ok || data.value.kind === "role")) return <Deletion name={name} task={deletion} back={back} />;
  if (!data.ok) {
    return (
      <Page title={name} icon={ICON[kind]} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const d = data.value;
  const base = `/iam/${kind}s/${encodeURIComponent(name)}`;
  const attachedArns = new Set(d.attached.map((p) => p.PolicyArn));
  const attachable = d.all.filter((p) => !attachedArns.has(p.Arn));
  const arn = d.kind === "role" ? d.role.Arn! : d.kind === "user" ? d.user.Arn! : d.group.Arn!;
  const path = d.kind === "role" ? d.role.Path : d.kind === "user" ? d.user.Path : d.group.Path;
  const tags = d.kind === "role" ? (d.role.Tags ?? []) : d.kind === "user" ? (d.user.Tags ?? []) : [];
  const boundary = d.kind === "role" ? d.role.PermissionsBoundary : d.kind === "user" ? d.user.PermissionsBoundary : undefined;
  const linked = d.kind === "role" && serviceLinked(d.role.Path);
  const who = d.kind === "role" ? trust(policyDocument(d.role.AssumeRolePolicyDocument), info.account) : null;

  const tabs =
    d.kind === "role"
      ? [
          { id: "permissions", label: "Permissions", count: d.attached.length + d.inline.length },
          { id: "trust", label: "Trust relationships" },
          { id: "tags", label: "Tags", count: tags.length || undefined },
        ]
      : d.kind === "user"
        ? [
            { id: "permissions", label: "Permissions", count: d.attached.length + d.inline.length },
            { id: "groups", label: "Groups", count: d.groups.length },
            { id: "tags", label: "Tags", count: tags.length || undefined },
            { id: "credentials", label: "Security credentials" },
          ]
        : [
            { id: "users", label: "Users", count: d.members.length },
            { id: "permissions", label: "Permissions", count: d.attached.length + d.inline.length },
          ];
  const active = tabs.find((t) => t.id === tab)?.id ?? tabs[0].id;

  const policyRow = (p: AttachedPolicy) => ({
    key: p.PolicyArn!,
    icon: <AwsIcon icon={ICONS.policy} size={22} />,
    title: p.PolicyName,
    meta: p.PolicyArn!.includes(":aws:policy/") ? <Pill>AWS managed</Pill> : undefined,
    href: `/iam/policy?arn=${encodeURIComponent(p.PolicyArn!)}`,
    actions: !linked && <ActionForm action={detachPolicy.bind(null, kind, name, p.PolicyArn!)} submit={`Detach ${p.PolicyName}`} icon={<Unlink size={15} />} />,
  });

  // What a delete takes with it, said in the confirmation (AWS's console
  // removes these first).
  const parts =
    d.kind === "user"
      ? [d.attached.length + d.inline.length && `${d.attached.length + d.inline.length} policies`, d.keys.length && `${d.keys.length} access keys`, d.groups.length && `${d.groups.length} group memberships`, d.login && "the console password", d.mfa.length && "MFA devices"]
      : d.kind === "role"
        ? [d.attached.length + d.inline.length && `${d.attached.length + d.inline.length} policies`, d.profiles.length && `${d.profiles.length} instance profiles`]
        : [d.attached.length + d.inline.length && `${d.attached.length + d.inline.length} policies`, d.members.length && `${d.members.length} members`];
  const cleanup = parts.filter(Boolean).join(", ");

  const actions = (
    <>
      {d.kind !== "group" && (
        <Link className="icon-button plain" href={`/iam/simulator?principal=${encodeURIComponent(arn)}`} aria-label="Simulate permissions" title="Simulate permissions">
          <FlaskConical size={16} aria-hidden />
        </Link>
      )}
      {d.kind === "role" && !linked && (
        <Sheet title="Edit role" label="Edit role" icon={<Pencil size={16} />} testId="edit-role">
          <ActionForm action={updateRole.bind(null, name)} submit="Save" testId="edit-role">
            <Field label="Description" rule={UpdateRole.Description}>
              <input name="description" defaultValue={d.role.Description} />
            </Field>
            <Field label="Maximum session duration (hours)" rule={{ type: "number", min: 1, max: 12 }}>
              <input name="hours" type="number" min={1} max={12} step="any" defaultValue={(d.role.MaxSessionDuration ?? 3600) / 3600} />
            </Field>
          </ActionForm>
        </Sheet>
      )}
      {d.kind !== "role" && (
        <Sheet title={`Edit ${kind}`} label={`Edit ${kind}`} icon={<Pencil size={16} />} testId={`edit-${kind}`}>
          <ActionForm action={renamePrincipal.bind(null, d.kind, name)} submit="Save" testId={`edit-${kind}`}>
            <Field label="Name" rule={d.kind === "user" ? RULES.userName : RULES.groupName} unique>
              <input name="name" required defaultValue={name} />
            </Field>
            <Field label="Path" rule={RULES.path}>
              <input name="path" defaultValue={path} />
            </Field>
          </ActionForm>
        </Sheet>
      )}
      {linked ? (
        <ActionForm
          action={deleteServiceLinkedRole.bind(null, name)}
          submit="Delete role"
          icon={<Trash2 size={16} />}
          tone="danger"
          confirm={`Delete ${name}? The service checks it no longer uses the role first.`}
          testId="delete-role"
        />
      ) : (
        <ActionForm
          action={deletePrincipal.bind(null, kind, name)}
          submit={`Delete ${kind}`}
          icon={<Trash2 size={16} />}
          tone="danger"
          confirm={cleanup ? `Delete ${name}? Its ${cleanup} are removed first.` : `Delete ${name}?`}
          testId={`delete-${kind}`}
        />
      )}
    </>
  );

  const permissions = (
    <>
      <Section
        title="Permissions policies"
        count={d.attached.length + d.inline.length}
        plain
        actions={
          !linked && (
            <>
              <Sheet title="Attach policy" label="Attach policy" icon={<Link2 size={16} />} testId="attach-policy">
                <ActionForm action={attachPolicy.bind(null, kind, name)} submit="Attach" testId="attach-policy">
                  <AttachFields known={attachable.map((p) => ({ arn: p.Arn!, name: p.PolicyName! }))} attached={[...attachedArns].filter((a): a is string => !!a)} />
                </ActionForm>
              </Sheet>
              <Sheet title="Inline policy" label="Create inline policy" icon={<Plus size={16} />} testId="inline-policy">
                <ActionForm action={putInlinePolicy.bind(null, kind, name)} submit="Create" testId="inline-policy">
                  <PolicyFields taken={d.inline} inline />
                </ActionForm>
              </Sheet>
            </>
          )
        }
      >
        <List
          label="Permissions"
          empty={<Empty icon={ICONS.policy} />}
          rows={[
            ...d.attached.map(policyRow),
            ...d.inline.map((p) => ({
              key: `inline:${p}`,
              icon: <Pencil size={18} />,
              title: p,
              subtitle: "Inline",
              href: `${base}/inline/${encodeURIComponent(p)}`,
              actions: !linked && (
                <ActionForm action={deleteInlinePolicy.bind(null, kind, name, p, false)} submit={`Delete ${p}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${p}?`} />
              ),
            })),
          ]}
        />
      </Section>
      {d.kind !== "group" && !linked && (
        <Section
          title="Permissions boundary"
          plain
          actions={
            <Sheet title="Permissions boundary" label={boundary ? "Change boundary" : "Set boundary"} icon={<ShieldCheck size={16} />} testId="set-boundary">
              <ActionForm action={putBoundary.bind(null, d.kind, name)} submit="Set boundary" testId="set-boundary">
                <Field label="Policy" rule={RULES.policyArn}>
                  <ResourcePicker kind="iam-policy" name="policyArn" required defaultValue={boundary?.PermissionsBoundaryArn} placeholder="Search managed policies, e.g. PowerUserAccess" />
                </Field>
              </ActionForm>
            </Sheet>
          }
        >
          {boundary?.PermissionsBoundaryArn && (
            <List
              label="Permissions boundary"
              rows={[
                {
                  key: boundary.PermissionsBoundaryArn,
                  icon: <ShieldCheck size={18} />,
                  title: boundary.PermissionsBoundaryArn.split("/").pop(),
                  subtitle: "Caps what the policies above can grant",
                  href: `/iam/policy?arn=${encodeURIComponent(boundary.PermissionsBoundaryArn)}`,
                  actions: <ActionForm action={deleteBoundary.bind(null, d.kind, name)} submit="Remove boundary" icon={<ShieldOff size={15} />} tone="danger" confirm="Remove the permissions boundary?" />,
                },
              ]}
            />
          )}
        </Section>
      )}
      {d.kind === "role" && (d.profiles.length > 0 || who?.services.includes("ec2.amazonaws.com")) && (
        <Section
          title="Instance profiles"
          count={d.profiles.length}
          plain
          actions={
            <Sheet title="Create instance profile" label="Create instance profile" icon={<Plus size={16} />} testId="create-instance-profile">
              <ActionForm action={createInstanceProfile.bind(null, name)} submit="Create" testId="create-instance-profile">
                <Field label="Name" rule={CreateInstanceProfile.InstanceProfileName} unique>
                  <input name="name" required defaultValue={d.profiles.some((p) => p.InstanceProfileName === name) ? "" : name} />
                </Field>
              </ActionForm>
            </Sheet>
          }
        >
          <List
            label="Instance profiles"
            rows={d.profiles.map((p) => ({
              key: p.InstanceProfileId!,
              icon: <AwsIcon icon={ICONS.role} size={22} />,
              title: p.InstanceProfileName,
              subtitle: p.Arn,
              href: `/iam/instance-profiles/${encodeURIComponent(p.InstanceProfileName!)}`,
            }))}
          />
        </Section>
      )}
    </>
  );

  let body;
  if (active === "permissions") body = permissions;
  else if (active === "trust" && d.kind === "role") {
    const doc = policyDocument(d.role.AssumeRolePolicyDocument);
    body = (
      <Section
        title="Trust policy"
        actions={
          !linked && (
            <Sheet title="Trust policy" label="Edit trust policy" icon={<Pencil size={16} />} testId="edit-trust">
              <ActionForm action={updateTrust.bind(null, name)} submit="Save" testId="edit-trust">
                <PolicyEditor label="Document" name="document" kind="trust" rows={14} required aria-label="Trust policy" rule={RULES.trustEdit} defaultValue={pretty(doc)} />
              </ActionForm>
            </Sheet>
          )
        }
      >
        <CodeBlock value={doc} label="Trust policy" />
      </Section>
    );
  } else if (active === "tags") {
    body = (
      <Section
        title="Tags"
        count={tags.length}
        actions={
          d.kind !== "group" && (
            <Sheet title="Tags" label="Edit tags" icon={<Tag size={16} />} testId="edit-tags">
              <ActionForm action={saveTags.bind(null, d.kind, name, tags.map((t) => t.Key!))} submit="Save" testId="edit-tags">
                <Field label="Tags" format="tags">
                  <textarea name="tags" rows={6} placeholder="team=payments" defaultValue={tags.map((t) => `${t.Key}=${t.Value}`).join("\n")} />
                </Field>
              </ActionForm>
            </Sheet>
          )
        }
      >
        {tags.length ? <Tags tags={tags} /> : <Empty>No tags</Empty>}
      </Section>
    );
  } else if (active === "groups" && d.kind === "user") {
    const joinable = d.everyGroup.filter((g) => !d.groups.some((m) => m.GroupName === g.GroupName));
    body = (
      <Section
        title="Groups"
        count={d.groups.length}
        plain
        actions={
          <Sheet title="Add to group" label="Add to group" icon={<UserPlus size={16} />} testId="add-to-group">
            <ActionForm action={addToGroup.bind(null, name)} submit="Add" testId="add-to-group">
              <Field label="Group" rule={RULES.group}>
                <select name="group" required>
                  {joinable.map((g) => (
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
          empty={<Empty icon={ICONS.users} />}
          rows={d.groups.map((g) => ({
            key: g.GroupId!,
            icon: <AwsIcon icon={ICONS.users} size={22} />,
            title: g.GroupName,
            href: `/iam/groups/${encodeURIComponent(g.GroupName!)}`,
            actions: <ActionForm action={removeFromGroup.bind(null, name, g.GroupName!)} submit={`Leave ${g.GroupName}`} icon={<UserMinus size={15} />} />,
          }))}
        />
      </Section>
    );
  } else if (active === "credentials" && d.kind === "user") {
    body = (
      <>
        <Section
          title="Console sign-in"
          plain
          actions={
            <>
              <Sheet title={d.login ? "Change console password" : "Enable console access"} label={d.login ? "Change console password" : "Enable console access"} icon={<LockKeyhole size={16} />} testId="console-password">
                <ActionForm action={saveLoginProfile.bind(null, name, !!d.login)} submit="Save" testId="console-password">
                  <Field label="Password" rule={CreateLoginProfile.Password} generate="password">
                    <input name="password" type="text" required autoComplete="new-password" />
                  </Field>
                  <label className="check">
                    <input type="checkbox" name="reset" defaultChecked={d.login?.PasswordResetRequired ?? true} /> Must create a new password at next sign-in
                  </label>
                </ActionForm>
              </Sheet>
              {d.login && (
                <ActionForm action={deleteLoginProfile.bind(null, name)} submit="Disable console access" icon={<ShieldOff size={16} />} tone="danger" confirm={`Disable console access for ${name}?`} testId="disable-console" />
              )}
            </>
          }
        >
          <Facts
            items={[
              ["Console access", d.login ? <Status key="c" tone="good">enabled</Status> : <Status key="c" tone="neutral">disabled</Status>],
              d.login && ["Password set", ago(d.login.CreateDate)],
              d.login?.PasswordResetRequired && ["Reset required", <Pill key="r" tone="warn">next sign-in</Pill>],
              d.user.PasswordLastUsed && ["Last sign-in", ago(d.user.PasswordLastUsed)],
            ]}
          />
        </Section>
        <Section title="Multi-factor authentication (MFA)" count={d.mfa.length} plain>
          <List
            label="MFA devices"
            empty={<Empty>—</Empty>}
            rows={d.mfa.map((m) => ({
              key: m.SerialNumber!,
              icon: <Smartphone size={18} />,
              title: m.SerialNumber!.split("/").pop(),
              subtitle: m.SerialNumber,
              meta: ago(m.EnableDate),
              actions: <ActionForm action={removeMfa.bind(null, name, m.SerialNumber!)} submit={`Remove ${m.SerialNumber}`} icon={<Trash2 size={15} />} tone="danger" confirm="Remove this MFA device?" />,
            }))}
          />
        </Section>
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
              const on = k.Status === "Active";
              const used = k.used?.LastUsedDate;
              return {
                key: k.AccessKeyId!,
                icon: <KeyRound size={18} />,
                title: <code>{k.AccessKeyId}</code>,
                subtitle: used ? `Used ${ago(used)} · ${k.used?.ServiceName} · ${k.used?.Region}` : `Created ${ago(k.CreateDate)} · never used`,
                meta: <Status tone={on ? "good" : "neutral"}>{on ? "Active" : "Inactive"}</Status>,
                actions: (
                  <>
                    <ActionForm
                      action={setAccessKey.bind(null, name, k.AccessKeyId!, !on)}
                      submit={on ? `Deactivate ${k.AccessKeyId}` : `Activate ${k.AccessKeyId}`}
                      icon={on ? <Pause size={15} /> : <Play size={15} />}
                    />
                    <ActionForm action={deleteAccessKey.bind(null, name, k.AccessKeyId!)} submit={`Delete ${k.AccessKeyId}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${k.AccessKeyId}?`} />
                  </>
                ),
              };
            })}
          />
        </Section>
      </>
    );
  } else if (active === "users" && d.kind === "group") {
    const addable = d.users.filter((u) => !d.members.some((m) => m.UserName === u.UserName));
    body = (
      <Section
        title="Users in this group"
        count={d.members.length}
        plain
        actions={
          <Sheet title="Add users" label="Add users" icon={<UserPlus size={16} />} testId="add-member">
            <ActionForm action={addMember.bind(null, name)} submit="Add" testId="add-member">
              <Field label="User" rule={RULES.member}>
                <select name="user" required>
                  {addable.map((u) => (
                    <option key={u.UserId}>{u.UserName}</option>
                  ))}
                </select>
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        <List
          label="Members"
          empty={<Empty icon={ICONS.user} />}
          rows={d.members.map((u) => ({
            key: u.UserId!,
            icon: <AwsIcon icon={ICONS.user} size={22} />,
            title: u.UserName,
            href: `/iam/users/${encodeURIComponent(u.UserName!)}`,
            meta: u.PasswordLastUsed ? `signed in ${ago(u.PasswordLastUsed)}` : undefined,
            actions: <ActionForm action={removeFromGroup.bind(null, u.UserName!, name)} submit={`Remove ${u.UserName}`} icon={<UserMinus size={15} />} />,
          }))}
        />
      </Section>
    );
  }

  const lastUsed = d.kind === "role" ? d.role.RoleLastUsed : undefined;
  return (
    <Page title={name} icon={ICON[kind]} back={back} subtitle={arn} actions={actions}>
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
          linked && ["Service-linked", <Pill key="sl" tone="info">managed by the service</Pill>],
          d.kind === "role" && d.role.Description && ["Description", d.role.Description],
          path && path !== "/" && ["Path", <code key="p">{path}</code>],
          lastUsed?.LastUsedDate ? ["Last used", `${ago(lastUsed.LastUsedDate)}${lastUsed.Region ? ` in ${lastUsed.Region}` : ""}`] : d.kind === "role" && ["Last used", <span key="n" className="muted">never</span>],
          d.kind === "user" && d.user.PasswordLastUsed && ["Console sign-in", ago(d.user.PasswordLastUsed)],
          d.kind === "user" && ["Console access", d.login ? "enabled" : "disabled"],
          d.kind === "user" && d.mfa.length === 0 && d.login && ["MFA", <Pill key="m" tone="warn">none</Pill>],
          d.kind === "role" && d.role.MaxSessionDuration !== 3600 && ["Max session", `${(d.role.MaxSessionDuration ?? 3600) / 3600} h`],
          boundary?.PermissionsBoundaryArn && [
            "Permissions boundary",
            <Link key="b" href={`/iam/policy?arn=${encodeURIComponent(boundary.PermissionsBoundaryArn)}`}>
              {boundary.PermissionsBoundaryArn.split("/").pop()}
            </Link>,
          ],
          d.kind === "role" &&
            d.profiles.length > 0 && [
              "Instance profile",
              d.profiles.map((p) => (
                <Link key={p.InstanceProfileId} href={`/iam/instance-profiles/${encodeURIComponent(p.InstanceProfileName!)}`}>
                  {p.InstanceProfileName}
                </Link>
              )),
            ],
          ["Created", ago(d.kind === "role" ? d.role.CreateDate : d.kind === "user" ? d.user.CreateDate : d.group.CreateDate)],
        ]}
      />
      <Segments label={`${kind} tabs`} items={tabs.map((t) => ({ label: t.label, href: t.id === tabs[0].id ? base : `${base}?tab=${t.id}`, active: active === t.id, count: t.count }))} />
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

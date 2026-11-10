import {
  DescribeAccountAssignmentCreationStatusCommand,
  DescribeAccountAssignmentDeletionStatusCommand,
  ListAccountAssignmentCreationStatusCommand,
  ListAccountAssignmentDeletionStatusCommand,
  type PermissionSet,
  type PrincipalType,
} from "@aws-sdk/client-sso-admin";
import type { Account } from "@aws-sdk/client-organizations";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, Field, List, Pill, Section, Sheet, Status } from "@mws-dashboard/ui";
import { Building2, KeyRound, Settings, Trash2 } from "lucide-react";
import Link from "next/link";

import { ICONS, ssoAdmin } from "../../lib/clients";
import { setId } from "../../lib/sso";
import { createAssignment, deleteAssignment } from "./actions";

/** Icon links to the pages the sidebar has no entry for. */
export function Links() {
  return (
    <>
      <Link className="icon-button plain" href="/identitycenter/accounts" aria-label="AWS accounts" title="AWS accounts">
        <Building2 size={16} aria-hidden />
      </Link>
      <Link className="icon-button plain" href="/identitycenter/settings" aria-label="Settings" title="Settings">
        <Settings size={16} aria-hidden />
      </Link>
    </>
  );
}

export interface AssignmentRow {
  account: string;
  set: string;
  type: PrincipalType;
  principal: string;
}

/** Account assignments, each with what it joins: who, which permission set, where. */
export function Assignments({
  instance,
  rows,
  names,
  sets,
  accounts,
  principals,
  fixed,
  show,
}: {
  instance: string;
  rows: AssignmentRow[];
  /** User and group display names by id. */
  names: Map<string, string>;
  sets: PermissionSet[];
  accounts: Account[];
  /** Offered in the create form as "USER:id" / "GROUP:id". */
  principals?: { value: string; label: string }[];
  fixed: { account?: string; principal?: string };
  /** What each row names: the principal (on an account) or the account (on a principal). */
  show: "principal" | "account";
}) {
  const setName = new Map(sets.map((s) => [s.PermissionSetArn!, s.Name!]));
  const accountName = new Map(accounts.map((a) => [a.Id!, a.Name!]));
  const create = (
    <Sheet title="Assign access" label="Assign users or groups" icon={<KeyRound size={16} />} testId="create-assignment">
      <ActionForm action={createAssignment.bind(null, instance, fixed)} submit="Assign" testId="create-assignment">
        {!fixed.account && (
          <Field label="AWS account">
            <select name="account" required>
              {accounts.map((a) => (
                <option key={a.Id} value={a.Id}>
                  {a.Name} ({a.Id})
                </option>
              ))}
            </select>
          </Field>
        )}
        {!fixed.principal && (
          <Field label="User or group">
            <select name="principal" required>
              {(principals ?? []).map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </select>
          </Field>
        )}
        <Field label="Permission set">
          <select name="set" required>
            {sets.map((s) => (
              <option key={s.PermissionSetArn} value={s.PermissionSetArn}>
                {s.Name}
              </option>
            ))}
          </select>
        </Field>
      </ActionForm>
    </Sheet>
  );
  return (
    <Section title="Assignments" count={rows.length} plain actions={sets.length > 0 && create}>
      <List
        label="Assignments"
        empty={<Empty icon={ICONS.policy}>{sets.length ? undefined : "Create a permission set to assign access"}</Empty>}
        rows={rows.map((r) => ({
          key: `${r.account}:${r.set}:${r.principal}`,
          icon:
            show === "account" ? (
              <AwsIcon icon="resource/AWSOrganizationsAccount" size={22} />
            ) : (
              <AwsIcon icon={r.type === "USER" ? ICONS.user : ICONS.users} size={22} />
            ),
          title:
            show === "account" ? (
              <Link href={`/identitycenter/accounts/${r.account}`}>{accountName.get(r.account) ?? r.account}</Link>
            ) : (
              <Link href={`/identitycenter/${r.type === "USER" ? "users" : "groups"}/${r.principal}`}>{names.get(r.principal) ?? r.principal}</Link>
            ),
          subtitle: show === "account" ? r.account : r.type === "USER" ? "User" : "Group",
          meta: (
            <Link href={`/identitycenter/permissionset?arn=${encodeURIComponent(r.set)}`}>
              <Pill icon={<KeyRound size={11} />}>{setName.get(r.set) ?? setId(r.set)}</Pill>
            </Link>
          ),
          actions: (
            <ActionForm
              action={deleteAssignment.bind(null, instance, r.account, r.set, r.type, r.principal)}
              submit={`Remove ${setName.get(r.set) ?? "assignment"} for ${names.get(r.principal) ?? r.principal} in ${r.account}`}
              icon={<Trash2 size={15} />}
              tone="danger"
              confirm="Remove this assignment? Its role is deleted from the account when it was the last one."
            />
          ),
        }))}
      />
    </Section>
  );
}

const TONE = { SUCCEEDED: "good", FAILED: "bad", IN_PROGRESS: "info" } as const;

/** Assignment changes still running, and the ones that failed in the last
 * day (with AWS's reason). Shown only when there are any; while one runs
 * the page refreshes itself. */
export async function Operations({ instance, account }: { instance: string; account?: string }) {
  const data = await load(async () => {
    const c = await ssoAdmin();
    const since = Date.now() - 86_400_000;
    const list = async (kind: "create" | "delete") => {
      const page = (NextToken: string | undefined) =>
        kind === "create"
          ? c.send(new ListAccountAssignmentCreationStatusCommand({ InstanceArn: instance, NextToken })).then((r) => ({ items: r.AccountAssignmentsCreationStatus, next: r.NextToken }))
          : c.send(new ListAccountAssignmentDeletionStatusCommand({ InstanceArn: instance, NextToken })).then((r) => ({ items: r.AccountAssignmentsDeletionStatus, next: r.NextToken }));
      const meta = (await all(page, (r) => r.items, (r) => r.next)).filter((m) => m.Status === "IN_PROGRESS" || (m.Status === "FAILED" && +new Date(m.CreatedDate!) > since));
      return Promise.all(
        meta.map(async (m) => {
          const s =
            kind === "create"
              ? (await c.send(new DescribeAccountAssignmentCreationStatusCommand({ InstanceArn: instance, AccountAssignmentCreationRequestId: m.RequestId }))).AccountAssignmentCreationStatus
              : (await c.send(new DescribeAccountAssignmentDeletionStatusCommand({ InstanceArn: instance, AccountAssignmentDeletionRequestId: m.RequestId }))).AccountAssignmentDeletionStatus;
          return { kind, ...m, ...s };
        }),
      );
    };
    const ops = [...(await list("create")), ...(await list("delete"))];
    return ops.filter((o) => !account || o.TargetId === account).sort((a, b) => +new Date(b.CreatedDate!) - +new Date(a.CreatedDate!));
  });
  if (!data.ok || data.value.length === 0) return null;
  return (
    <Section title="Recent changes" count={data.value.length} plain>
      <List
        label="Assignment operations"
        rows={data.value.map((o) => ({
          key: o.RequestId!,
          title: `${o.kind === "create" ? "Assign" : "Remove"} ${setId(o.PermissionSetArn ?? "")} in ${o.TargetId}`,
          subtitle: o.FailureReason,
          meta: (
            <>
              <Status tone={TONE[o.Status as keyof typeof TONE] ?? "neutral"}>{o.Status === "IN_PROGRESS" ? "in progress" : o.Status!.toLowerCase()}</Status>
              <span>{ago(o.CreatedDate)}</span>
            </>
          ),
        }))}
      />
    </Section>
  );
}

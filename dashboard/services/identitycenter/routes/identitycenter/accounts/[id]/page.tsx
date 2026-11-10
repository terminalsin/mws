import { load } from "@mws-dashboard/aws";
import { ErrorNotice, Facts, Page } from "@mws-dashboard/ui";
import type { Metadata } from "next";
import Link from "next/link";

import { accounts as listAccounts, assignmentsInAccount, groups as listGroups, instance as loadInstance, permissionSets, users as listUsers } from "../../../../lib/sso";
import { Assignments, Operations, type AssignmentRow } from "../../parts";

type Props = { params: Promise<{ id: string }> };

export const metadata: Metadata = { title: "AWS account" };

/** Who has which permission set in one account, as AWS's console shows it. */
export default async function Account({ params }: Props) {
  const { id } = await params;
  const back = { href: "/identitycenter/accounts", label: "AWS accounts" };
  const data = await load(async () => {
    const inst = await loadInstance();
    if (!inst) throw new Error("Identity Center is not enabled in this Region");
    const [accounts, sets, users, groups] = await Promise.all([listAccounts(inst.owner), inst.permissionSets ? permissionSets(inst.arn) : [], listUsers(inst.store), listGroups(inst.store)]);
    const assignments = (await Promise.all(sets.map((s) => assignmentsInAccount(inst.arn, id, s.PermissionSetArn!)))).flat();
    return { inst, account: accounts.find((a) => a.Id === id), sets, users, groups, assignments };
  });
  if (!data.ok) {
    return (
      <Page title={id} icon="resource/AWSOrganizationsAccount" back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { inst, account, sets, users, groups, assignments } = data.value;
  const names = new Map<string, string>([...users.map((u) => [u.UserId!, u.UserName!] as [string, string]), ...groups.map((g) => [g.GroupId!, g.DisplayName!] as [string, string])]);
  const rows: AssignmentRow[] = assignments.map((a) => ({ account: id, set: a.PermissionSetArn!, type: a.PrincipalType!, principal: a.PrincipalId! }));
  return (
    <Page title={account?.Name ?? id} icon="resource/AWSOrganizationsAccount" back={back} subtitle={id}>
      <Facts
        items={[
          account?.Email && ["Email", account.Email],
          id === inst.owner && ["Management account", "yes"],
          account?.Arn && [
            "Organizations",
            <Link key="o" href={`/organizations/accounts/${id}`}>
              Account details
            </Link>,
          ],
        ]}
      />
      <Operations instance={inst.arn} account={id} />
      <Assignments
        instance={inst.arn}
        rows={rows}
        names={names}
        sets={sets}
        accounts={account ? [account] : [{ Id: id }]}
        principals={[...groups.map((g) => ({ value: `GROUP:${g.GroupId}`, label: `${g.DisplayName} (group)` })), ...users.map((u) => ({ value: `USER:${u.UserId}`, label: u.UserName! }))]}
        fixed={{ account: id }}
        show="principal"
      />
    </Page>
  );
}

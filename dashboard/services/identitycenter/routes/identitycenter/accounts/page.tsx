import { ListPermissionSetsProvisionedToAccountCommand } from "@aws-sdk/client-sso-admin";
import { all, load } from "@mws-dashboard/aws";
import { AwsIcon, Empty, ErrorNotice, List, Page, Pill } from "@mws-dashboard/ui";
import { KeyRound } from "lucide-react";
import type { Metadata } from "next";

import { ssoAdmin } from "../../../lib/clients";
import { accounts as listAccounts, instance as loadInstance } from "../../../lib/sso";
import { Links, Operations } from "../parts";

export const metadata: Metadata = { title: "AWS accounts" };

/** The organization's accounts, with how many permission sets each has. */
export default async function Accounts() {
  const data = await load(async () => {
    const inst = await loadInstance();
    if (!inst) throw new Error("Identity Center is not enabled in this Region");
    const c = await ssoAdmin();
    const accounts = await listAccounts(inst.owner);
    const sets = await Promise.all(
      accounts.map((a) =>
        all((NextToken) => c.send(new ListPermissionSetsProvisionedToAccountCommand({ InstanceArn: inst.arn, AccountId: a.Id, NextToken })), (r) => r.PermissionSets, (r) => r.NextToken).catch(() => []),
      ),
    );
    return { inst, accounts: accounts.map((a, i) => ({ a, sets: sets[i].length })) };
  });
  if (!data.ok) {
    return (
      <Page title="AWS accounts" actions={<Links />}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { inst, accounts } = data.value;
  return (
    <Page title="AWS accounts" actions={<Links />}>
      <Operations instance={inst.arn} />
      <List
        label="AWS accounts"
        empty={<Empty icon="resource/AWSOrganizationsAccount" />}
        rows={accounts.map(({ a, sets }) => ({
          key: a.Id!,
          icon: <AwsIcon icon={a.Id === inst.owner ? "resource/AWSOrganizationsManagementAccount" : "resource/AWSOrganizationsAccount"} size={22} />,
          title: a.Name,
          subtitle: [a.Id, a.Email].filter(Boolean).join(" · "),
          href: `/identitycenter/accounts/${a.Id}`,
          meta: sets > 0 && (
            <Pill icon={<KeyRound size={11} />} title="Permission sets provisioned">
              {sets}
            </Pill>
          ),
        }))}
      />
    </Page>
  );
}

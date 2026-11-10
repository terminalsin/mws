import "server-only";

import { ACMPCAClient, ListCertificateAuthoritiesCommand } from "@aws-sdk/client-acm-pca";
import { DescribeOrganizationCommand, ListAccountsCommand, ListOrganizationalUnitsForParentCommand, ListRootsCommand, OrganizationsClient } from "@aws-sdk/client-organizations";
import { RAMClient } from "@aws-sdk/client-ram";
import { client, frameInfo } from "@mws-dashboard/aws";

export const ram = () => client(RAMClient);

export const ICONS = {
  organizations: "service/AWSOrganizations",
  account: "resource/AWSOrganizationsAccount",
  ou: "resource/AWSOrganizationsOrganizationalUnit",
  ram: "service/AWSResourceAccessManager",
};

const quietly = async <T,>(read: () => Promise<T>, fallback: T): Promise<T> => {
  try {
    return await read();
  } catch {
    return fallback;
  }
};

/** What the create form suggests: the resources this account can share
 * (Private CAs) and the principals in its organization. */
export async function shareTargets() {
  const [info, cas, principals] = await Promise.all([
    frameInfo(),
    quietly(async () => ((await (await client(ACMPCAClient)).send(new ListCertificateAuthoritiesCommand({}))).CertificateAuthorities ?? []).filter((c) => c.Status !== "DELETED").map((c) => c.Arn!), [] as string[]),
    quietly(async () => {
      const orgs = await client(OrganizationsClient);
      const [org, accounts, roots] = await Promise.all([
        orgs.send(new DescribeOrganizationCommand({})),
        orgs.send(new ListAccountsCommand({})),
        orgs.send(new ListRootsCommand({})),
      ]);
      const ous = await Promise.all((roots.Roots ?? []).map((r) => orgs.send(new ListOrganizationalUnitsForParentCommand({ ParentId: r.Id! }))));
      return [org.Organization?.Arn, ...ous.flatMap((o) => o.OrganizationalUnits ?? []).map((u) => u.Arn), ...(accounts.Accounts ?? []).map((a) => a.Id)].filter((x): x is string => !!x);
    }, [] as string[]),
  ]);
  return {
    resources: cas,
    // You don't share with yourself.
    principals: principals.filter((p) => p !== info.account),
    caArn: info.account ? `arn:aws:acm-pca:${info.region}:${info.account}:certificate-authority/{}` : undefined,
  };
}

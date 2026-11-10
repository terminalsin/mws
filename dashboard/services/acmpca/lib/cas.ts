import "server-only";

import { ListCertificateAuthoritiesCommand } from "@aws-sdk/client-acm-pca";
import { all } from "@mws-dashboard/aws";

import { pca } from "./clients";

/** Every CA in the account and Region (ListCertificateAuthorities pages at 100). */
export async function listAuthorities() {
  const c = await pca();
  return all((NextToken) => c.send(new ListCertificateAuthoritiesCommand({ NextToken })), (r) => r.CertificateAuthorities, (r) => r.NextToken);
}

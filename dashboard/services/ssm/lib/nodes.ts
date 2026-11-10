import "server-only";

import { DescribeInstanceInformationCommand, ListDocumentsCommand, type DocumentFilter, type DocumentKeyValuesFilter } from "@aws-sdk/client-ssm";
import { all } from "@mws-dashboard/aws";

import { ssm } from "./clients";

/** Every managed node (DescribeInstanceInformation pages at 50). */
export async function listNodes() {
  const c = await ssm();
  return all((NextToken) => c.send(new DescribeInstanceInformationCommand({ NextToken, MaxResults: 50 })), (r) => r.InstanceInformationList, (r) => r.NextToken);
}

/** Documents matching filters, all pages. */
export async function listDocuments(Filters: DocumentKeyValuesFilter[] = [], DocumentFilterList?: DocumentFilter[]) {
  const c = await ssm();
  return all((NextToken) => c.send(new ListDocumentsCommand({ NextToken, MaxResults: 50, Filters: Filters.length ? Filters : undefined, DocumentFilterList })), (r) => r.DocumentIdentifiers, (r) => r.NextToken);
}

/** A node's display name: its Name tag or computer name, else its id. */
export const nodeName = (n: { Name?: string; ComputerName?: string; InstanceId?: string }) => n.Name || n.ComputerName || n.InstanceId || "";

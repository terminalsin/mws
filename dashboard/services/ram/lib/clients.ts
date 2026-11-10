import "server-only";

import { RAMClient } from "@aws-sdk/client-ram";
import { client } from "@mws-dashboard/aws";

export const ram = () => client(RAMClient);

export const ICONS = {
  organizations: "service/AWSOrganizations",
  account: "resource/AWSOrganizationsAccount",
  ou: "resource/AWSOrganizationsOrganizationalUnit",
  ram: "service/AWSResourceAccessManager",
};

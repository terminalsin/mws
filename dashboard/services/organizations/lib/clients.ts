import "server-only";

import { OrganizationsClient } from "@aws-sdk/client-organizations";
import { client } from "@mws-dashboard/aws";

export const organizations = () => client(OrganizationsClient);

export const ICONS = {
  organizations: "service/AWSOrganizations",
  account: "resource/AWSOrganizationsAccount",
  management: "resource/AWSOrganizationsManagementAccount",
  ou: "resource/AWSOrganizationsOrganizationalUnit",
  policy: "resource/AWSIdentityAccessManagementPermissions",
};

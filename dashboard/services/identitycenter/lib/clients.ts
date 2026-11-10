import "server-only";

import { IdentitystoreClient } from "@aws-sdk/client-identitystore";
import { SSOAdminClient } from "@aws-sdk/client-sso-admin";
import { client } from "@mws-dashboard/aws";

export const ssoAdmin = () => client(SSOAdminClient);
export const identitystore = () => client(IdentitystoreClient);

export const ICONS = {
  identitycenter: "service/AWSIAMIdentityCenter",
  user: "resource/User",
  users: "resource/Users",
  policy: "resource/AWSIdentityAccessManagementPermissions",
};

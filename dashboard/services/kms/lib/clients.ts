import "server-only";

import { KMSClient } from "@aws-sdk/client-kms";
import { client } from "@mws-dashboard/aws";

export const kms = () => client(KMSClient);

export const ICONS = {
  key: "resource/AWSIdentityAccessManagementDataEncryptionKey",
};

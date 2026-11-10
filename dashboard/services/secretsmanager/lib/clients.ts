import "server-only";

import { SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { client } from "@mws-dashboard/aws";

export const secrets = () => client(SecretsManagerClient);

export const ICONS = {
  secrets: "service/AWSSecretsManager",
};

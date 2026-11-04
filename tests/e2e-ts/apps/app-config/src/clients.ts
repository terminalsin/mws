import { KMSClient } from "@aws-sdk/client-kms";
import { SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { SSMClient } from "@aws-sdk/client-ssm";

export const kms = new KMSClient({});
export const secrets = new SecretsManagerClient({});
export const ssm = new SSMClient({});

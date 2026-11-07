import "server-only";

import { IAMClient } from "@aws-sdk/client-iam";
import { KMSClient } from "@aws-sdk/client-kms";
import { SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { SSMClient } from "@aws-sdk/client-ssm";
import { client } from "@mws-dashboard/aws";

export const iam = () => client(IAMClient);
export const kms = () => client(KMSClient);
export const secrets = () => client(SecretsManagerClient);
export const ssm = () => client(SSMClient);

/** IAM returns policy documents URL-encoded. */
export function policyDocument(doc: string | undefined) {
  if (!doc) return undefined;
  try {
    return decodeURIComponent(doc);
  } catch {
    return doc;
  }
}

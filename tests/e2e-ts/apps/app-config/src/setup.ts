// What a deployment pipeline would create for one stage of the app.
import { CreateAliasCommand, CreateKeyCommand } from "@aws-sdk/client-kms";
import { CreateSecretCommand } from "@aws-sdk/client-secrets-manager";
import { PutParameterCommand } from "@aws-sdk/client-ssm";
import { kms, secrets, ssm } from "./clients.js";
import type { DatabaseCredentials } from "./config.js";

export interface Stage {
  keyId: string;
  keyArn: string;
  aliasName: string;
  secretId: string;
}

export async function provisionStage(app: string, stage: string, database: DatabaseCredentials): Promise<Stage> {
  const { KeyMetadata } = await kms.send(
    new CreateKeyCommand({ Description: `${app} ${stage} configuration`, Tags: [{ TagKey: "app", TagValue: app }] }),
  );
  const aliasName = `alias/${app}-${stage}`;
  await kms.send(new CreateAliasCommand({ AliasName: aliasName, TargetKeyId: KeyMetadata!.KeyId }));

  const secretId = `${app}/${stage}/database`;
  await secrets.send(
    new CreateSecretCommand({ Name: secretId, KmsKeyId: aliasName, SecretString: JSON.stringify(database) }),
  );

  const put = (name: string, value: string, type: "String" | "StringList" | "SecureString" = "String") =>
    ssm.send(
      new PutParameterCommand({
        Name: `/${app}/${stage}/${name}`,
        Value: value,
        Type: type,
        KeyId: type === "SecureString" ? aliasName : undefined,
      }),
    );
  await put("http/port", "8080");
  await put("features", "invoices,refunds", "StringList");
  await put("stripe/api-key", "sk_test_51Hx", "SecureString");
  await put("database/secret-id", secretId);

  return { keyId: KeyMetadata!.KeyId!, keyArn: KeyMetadata!.Arn!, aliasName, secretId };
}

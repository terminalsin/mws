import { CreateAccessKeyCommand, CreateUserCommand, PutUserPolicyCommand } from "@aws-sdk/client-iam";
import { IAMClient } from "@aws-sdk/client-iam";
import { PutSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { GetParameterCommand, PutParameterCommand, SSMClient } from "@aws-sdk/client-ssm";
import { randomBytes } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { secrets } from "../src/clients.js";
import { loadConfig, readDatabaseCredentials, readParameters, readSecretThroughParameterStore } from "../src/config.js";
import { open, seal } from "../src/envelope.js";
import { provisionStage, type Stage } from "../src/setup.js";

const app = `billing-${randomBytes(4).toString("hex")}`;
const database = { engine: "postgres", host: "db.internal", port: 5432, username: "billing", password: "s3cr3t!" };
let stage: Stage;

beforeAll(async () => {
  stage = await provisionStage(app, "prod", database);
});

describe("application config", () => {
  it("loads typed settings from Parameter Store and Secrets Manager", async () => {
    expect(await loadConfig(app, "prod")).toEqual({
      port: 8080,
      features: ["invoices", "refunds"],
      stripeApiKey: "sk_test_51Hx",
      database,
    });
  });

  it("pages through large parameter hierarchies", async () => {
    const ssm = new SSMClient({});
    for (let i = 0; i < 25; i++) {
      await ssm.send(new PutParameterCommand({ Name: `/${app}/flags/flag-${i}`, Value: String(i % 2 === 0), Type: "String" }));
    }
    const flags = await readParameters(`/${app}/flags`);
    expect(flags.size).toBe(25);
    expect(flags.get("flag-24")).toBe("true");
  });

  it("returns SecureStrings encrypted unless decryption is asked for", async () => {
    const ssm = new SSMClient({});
    const { Parameter } = await ssm.send(new GetParameterCommand({ Name: `/${app}/prod/stripe/api-key` }));
    expect(Parameter!.Type).toBe("SecureString");
    expect(Parameter!.Value).not.toBe("sk_test_51Hx");
  });

  it("keeps the previous secret version during a credential rotation", async () => {
    const rotated = { ...database, password: "n3w-p4ssw0rd" };
    await secrets.send(new PutSecretValueCommand({ SecretId: stage.secretId, SecretString: JSON.stringify(rotated) }));

    expect(await readDatabaseCredentials(stage.secretId)).toEqual(rotated);
    expect(await readDatabaseCredentials(stage.secretId, "AWSPREVIOUS")).toEqual(database);
    expect(JSON.parse(await readSecretThroughParameterStore(stage.secretId))).toEqual(rotated);
  });

  it("round-trips a record through envelope encryption", async () => {
    const context = { tenant: "acme", record: "invoice-1001" };
    const sealed = await seal(stage.aliasName, "IBAN NL91 ABNA 0417 1643 00", context);
    expect(sealed.ciphertext).not.toContain("IBAN");
    expect(await open(sealed, context)).toBe("IBAN NL91 ABNA 0417 1643 00");
  });

  it("refuses to open a record with the wrong encryption context", async () => {
    const sealed = await seal(stage.keyArn, "secret", { record: "invoice-1001" });
    await expect(open(sealed, { record: "invoice-1002" })).rejects.toMatchObject({
      name: "InvalidCiphertextException",
    });
  });

  it("denies SecureString decryption to a principal without kms:Decrypt", async () => {
    // A service user that may read parameters but not use the KMS key.
    const iam = new IAMClient({});
    const userName = `${app}-reader`;
    await iam.send(new CreateUserCommand({ UserName: userName }));
    await iam.send(
      new PutUserPolicyCommand({
        UserName: userName,
        PolicyName: "read-config",
        PolicyDocument: JSON.stringify({
          Version: "2012-10-17",
          Statement: [{ Effect: "Allow", Action: "ssm:GetParameter*", Resource: "*" }],
        }),
      }),
    );
    const { AccessKey } = await iam.send(new CreateAccessKeyCommand({ UserName: userName }));
    const asReader = new SSMClient({
      credentials: { accessKeyId: AccessKey!.AccessKeyId!, secretAccessKey: AccessKey!.SecretAccessKey! },
    });

    const plain = await asReader.send(new GetParameterCommand({ Name: `/${app}/prod/http/port` }));
    expect(plain.Parameter!.Value).toBe("8080");
    await expect(
      asReader.send(new GetParameterCommand({ Name: `/${app}/prod/stripe/api-key`, WithDecryption: true })),
    ).rejects.toMatchObject({ name: "AccessDeniedException" });
  });
});

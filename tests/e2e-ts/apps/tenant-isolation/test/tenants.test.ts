import { GetObjectCommand, ListObjectsV2Command, S3Client } from "@aws-sdk/client-s3";
import { AssumeRoleCommand, GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { randomBytes } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { provision, type Deployment } from "../src/provision.js";
import { TenantStorage } from "../src/tenant-storage.js";

let deployment: Deployment;
let acme: TenantStorage;
let globex: TenantStorage;

beforeAll(async () => {
  deployment = await provision(`saas-${randomBytes(4).toString("hex")}`);
  acme = new TenantStorage(deployment, "acme");
  globex = new TenantStorage(deployment, "globex");
});

describe("tenant isolation", () => {
  it("lets each tenant read and list its own files", async () => {
    await acme.write("invoices/1001.json", '{"amount": 120}');
    await acme.write("invoices/1002.json", '{"amount": 80}');
    await globex.write("invoices/1001.json", '{"amount": 999}');

    expect(await acme.read("invoices/1001.json")).toBe('{"amount": 120}');
    expect(await globex.read("invoices/1001.json")).toBe('{"amount": 999}');
    expect((await acme.list()).sort()).toEqual(["invoices/1001.json", "invoices/1002.json"]);
  });

  it("denies a tenant session another tenant's objects", async () => {
    await globex.write("secret.txt", "globex only");
    // The bug the policy guards against: acme's session asking for globex's key.
    await expect(
      acme.s3.send(new GetObjectCommand({ Bucket: deployment.bucket, Key: "tenants/globex/secret.txt" })),
    ).rejects.toMatchObject({ name: "AccessDenied", $metadata: { httpStatusCode: 403 } });
    await expect(
      acme.s3.send(new ListObjectsV2Command({ Bucket: deployment.bucket, Prefix: "tenants/globex/" })),
    ).rejects.toMatchObject({ name: "AccessDenied" });
    await expect(
      acme.s3.send(new ListObjectsV2Command({ Bucket: deployment.bucket })),
    ).rejects.toMatchObject({ name: "AccessDenied" });
  });

  it("runs tenant requests as a tagged assumed-role session", async () => {
    const sts = new STSClient({ credentials: acme.s3.config.credentials });
    const identity = await sts.send(new GetCallerIdentityCommand({}));
    const roleName = deployment.roleArn.split("/").pop();
    expect(identity.Arn).toBe(`arn:aws:sts::${deployment.accountId}:assumed-role/${roleName}/tenant-acme`);
    expect(identity.Account).toBe(deployment.accountId);
  });

  it("refuses to assume the role without a tenant tag", async () => {
    const sts = new STSClient({ credentials: deployment.backendCredentials });
    await expect(
      sts.send(new AssumeRoleCommand({ RoleArn: deployment.roleArn, RoleSessionName: "untagged" })),
    ).rejects.toMatchObject({ name: "AccessDenied", $metadata: { httpStatusCode: 403 } });
  });

  it("gives the backend user no direct access to the data", async () => {
    const backend = new S3Client({ credentials: deployment.backendCredentials, forcePathStyle: true });
    await expect(
      backend.send(new GetObjectCommand({ Bucket: deployment.bucket, Key: "tenants/acme/invoices/1001.json" })),
    ).rejects.toMatchObject({ name: "AccessDenied" });
  });
});

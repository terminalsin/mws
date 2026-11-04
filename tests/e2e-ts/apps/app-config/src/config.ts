// Loads an application's settings from a Parameter Store hierarchy such as
//
//   /billing/prod/http/port            String       "8080"
//   /billing/prod/features             StringList   "invoices,refunds"
//   /billing/prod/stripe/api-key       SecureString (KMS encrypted)
//
// and its database credentials from Secrets Manager.
import { GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { GetParameterCommand, paginateGetParametersByPath } from "@aws-sdk/client-ssm";
import { secrets, ssm } from "./clients.js";

export interface AppConfig {
  port: number;
  features: string[];
  stripeApiKey: string;
  database: DatabaseCredentials;
}

export interface DatabaseCredentials {
  engine: string;
  host: string;
  port: number;
  username: string;
  password: string;
}

/** Every parameter under `path`, keyed by its name relative to the path. */
export async function readParameters(path: string): Promise<Map<string, string>> {
  const values = new Map<string, string>();
  // The paginator follows NextToken; Parameter Store returns at most 10 per page.
  for await (const page of paginateGetParametersByPath(
    { client: ssm },
    { Path: path, Recursive: true, WithDecryption: true },
  )) {
    for (const p of page.Parameters ?? []) {
      values.set(p.Name!.slice(path.length + 1), p.Value!);
    }
  }
  return values;
}

export async function readDatabaseCredentials(secretId: string, versionStage = "AWSCURRENT"): Promise<DatabaseCredentials> {
  const { SecretString } = await secrets.send(new GetSecretValueCommand({ SecretId: secretId, VersionStage: versionStage }));
  return JSON.parse(SecretString!) as DatabaseCredentials;
}

/**
 * Secrets Manager secrets can also be read through Parameter Store, which
 * is handy for tools that only speak SSM.
 */
export async function readSecretThroughParameterStore(secretId: string): Promise<string> {
  const { Parameter } = await ssm.send(
    new GetParameterCommand({ Name: `/aws/reference/secretsmanager/${secretId}`, WithDecryption: true }),
  );
  return Parameter!.Value!;
}

export async function loadConfig(app: string, stage: string): Promise<AppConfig> {
  const params = await readParameters(`/${app}/${stage}`);
  const required = (name: string) => {
    const value = params.get(name);
    if (value === undefined) throw new Error(`missing parameter /${app}/${stage}/${name}`);
    return value;
  };
  return {
    port: Number(required("http/port")),
    features: required("features").split(","),
    stripeApiKey: required("stripe/api-key"),
    database: await readDatabaseCredentials(required("database/secret-id")),
  };
}

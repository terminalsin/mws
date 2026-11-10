import "server-only";

import { DescribeRepositoriesCommand, ECRClient } from "@aws-sdk/client-ecr";
import { ECRPUBLICClient } from "@aws-sdk/client-ecr-public";
import { all, client, endpoint, region } from "@mws-dashboard/aws";

export const ecr = () => client(ECRClient);
// ECR Public lives in us-east-1 only, whatever Region the console is in.
export const ecrPublic = () => client(ECRPUBLICClient, { region: "us-east-1" });

export const ICONS = {
  ecr: "service/AmazonElasticContainerRegistry",
  repo: "resource/AmazonElasticContainerRegistryRegistry",
  image: "resource/AmazonElasticContainerRegistryImage",
};

export const SEVERITY_TONE: Record<string, "bad" | "warn" | "neutral"> = { CRITICAL: "bad", HIGH: "bad", MEDIUM: "warn", LOW: "neutral", INFORMATIONAL: "neutral", UNDEFINED: "neutral" };

export const repoHref = (name: string, tab?: string) => `/ecr/repo?name=${encodeURIComponent(name)}${tab ? `&tab=${tab}` : ""}`;
export const imageHref = (repo: string, digest: string) => `/ecr/image?repo=${encodeURIComponent(repo)}&digest=${encodeURIComponent(digest)}`;
export const publicHref = (name: string) => `/ecr/public?name=${encodeURIComponent(name)}`;

export const links = {
  key: (arn: string) => `/kms/key?id=${encodeURIComponent(arn.split("/").pop() ?? arn)}`,
  role: (arn: string) => `/iam/roles/${encodeURIComponent(arn.split("/").pop() ?? arn)}`,
  secret: (arn: string) => `/secrets/secret?id=${encodeURIComponent(arn)}`,
};

export async function repositories() {
  const c = await ecr();
  return all(
    (nextToken) => c.send(new DescribeRepositoriesCommand({ nextToken })),
    (r) => r.repositories,
    (r) => r.nextToken,
  );
}

/** Push commands that reach this MWS: repository URIs name AWS's registry
 * (`<account>.dkr.ecr.<region>.amazonaws.com`) unless MWS runs with
 * `MWS_ECR_REGISTRY_HOST`; MWS also serves the registry on its own address,
 * taking the account and Region from the login password. */
export async function pushCommands(uri: string, cli = "ecr") {
  const r = await region();
  const mws = endpoint();
  const host = new URL(mws).host;
  const [registry, ...path] = uri.split("/");
  const target = registry.endsWith(".amazonaws.com") ? `${host}/${path.join("/")}` : uri;
  const login = target.split("/")[0];
  return [
    `aws ${cli} get-login-password --region ${cli === "ecr-public" ? "us-east-1" : r} --endpoint-url ${mws} | docker login --username AWS --password-stdin ${login}`,
    `docker tag app:latest ${target}:latest`,
    `docker push ${target}:latest`,
  ].join("\n");
}

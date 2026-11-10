// Console pages for the resources ASFF findings name, by ARN or by type.
const enc = encodeURIComponent;

/** The console page for a finding's resource (`Resources[].Id`, an ARN or
 * an id, with its ASFF `Type`), when the console has one. */
export function resourceHref(id: string | undefined, type?: string): string | undefined {
  if (!id) return undefined;
  const arn = id.startsWith("arn:") ? id.split(":") : null;
  const svc = arn?.[2];
  const rest = arn ? arn.slice(5).join(":") : id;
  if (type === "AwsS3Bucket" || svc === "s3") return `/s3/${enc(rest.split("/")[0])}`;
  if (type === "AwsEc2Instance" || /^instance\//.test(rest)) return `/ec2/instance?id=${enc(rest.split("/").pop()!)}`;
  if (type === "AwsEc2Vpc" || /^vpc\//.test(rest)) return `/vpc/${enc(rest.split("/").pop()!)}`;
  if (svc === "iam" && rest.startsWith("role/")) return `/iam/roles/${enc(rest.split("/").pop()!)}`;
  if (svc === "iam" && rest.startsWith("user/")) return `/iam/users/${enc(rest.split("/").pop()!)}`;
  if (svc === "iam" && rest.startsWith("policy/")) return `/iam/policy?arn=${enc(id)}`;
  if (type === "AwsIamAccessKey") return undefined;
  if (svc === "lambda") return `/lambda/${enc(rest.split(":")[1] ?? rest)}`;
  if (svc === "kms" && rest.startsWith("key/")) return `/kms/key?id=${enc(rest.slice(4))}`;
  if (svc === "sqs") return `/sqs/${enc(rest)}`;
  if (svc === "sns") return `/sns/topic?arn=${enc(id)}`;
  if (svc === "secretsmanager") return `/secrets/secret?id=${enc(id)}`;
  if (svc === "eks" && rest.startsWith("cluster/")) return `/eks/cluster?name=${enc(rest.slice(8))}`;
  if (svc === "rds" && rest.startsWith("db:")) return `/rds/db?id=${enc(rest.slice(3))}`;
  if (svc === "logs") return `/logs/group?name=${enc(rest.replace(/^log-group:/, "").replace(/:\*$/, ""))}`;
  if (svc === "cloudtrail") return "/cloudtrail";
  if (svc === "guardduty") return "/guardduty";
  return undefined;
}

/** The console page of the finding in the product that sent it (GuardDuty
 * findings arrive with their GuardDuty ARN as the ASFF Id). */
export function productHref(findingId: string | undefined, productArn: string | undefined): string | undefined {
  const gd = findingId?.match(/:guardduty:[^:]*:\d*:detector\/[^/]+\/finding\/([^/]+)$/);
  if (gd) return `/guardduty/finding?id=${enc(gd[1])}`;
  if (productArn?.endsWith("/guardduty")) return "/guardduty";
  if (productArn?.endsWith("/inspector")) return undefined;
  return undefined;
}

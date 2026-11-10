// Console pages for the resources an ARN names, so related resources link
// to each other across services (by URL: services never import each other).

export interface ArnParts {
  partition: string;
  service: string;
  region: string;
  account: string;
  resource: string;
}

export function parseArn(arn: string | undefined | null): ArnParts | null {
  if (!arn?.startsWith("arn:")) return null;
  const [, partition = "", service = "", region = "", account = "", ...rest] = arn.split(":");
  return { partition, service, region, account, resource: rest.join(":") };
}

/** The console page of the resource an ARN names, or undefined when the
 * console has none. */
export function arnHref(arn: string | undefined | null): string | undefined {
  const a = parseArn(arn);
  if (!a) return undefined;
  const q = encodeURIComponent;
  const [kind, ...rest] = a.resource.split(/[:/]/);
  const tail = rest.join("/");
  switch (a.service) {
    case "sqs":
      return `/sqs/${q(a.resource)}`;
    case "sns":
      return a.resource.split(":").length > 1 ? `/sns/subscription?arn=${q(arn!)}` : `/sns/topic?arn=${q(arn!)}`;
    case "lambda":
      return kind === "function" ? `/lambda/${q(rest[0] ?? "")}` : kind === "layer" ? `/lambda/layers/${q(rest[0] ?? "")}` : undefined;
    case "kinesis":
      return kind === "stream" ? `/kinesis/stream?name=${q(rest[0] ?? "")}` : undefined;
    case "firehose":
      return kind === "deliverystream" ? `/firehose/stream?name=${q(tail)}` : undefined;
    case "logs":
      return kind === "log-group" ? `/logs/group?name=${q(a.resource.split(":")[1] ?? "")}` : undefined;
    case "iam":
      return kind === "role" ? `/iam/roles/${q(rest[rest.length - 1] ?? "")}` : kind === "user" ? `/iam/users/${q(rest[rest.length - 1] ?? "")}` : undefined;
    case "kms":
      return kind === "key" ? `/kms/key?id=${q(rest[0] ?? "")}` : undefined;
    case "s3":
      return a.resource ? `/s3/${q(a.resource.split("/")[0])}` : undefined;
    case "events": {
      if (kind === "rule") {
        const parts = a.resource.slice("rule/".length).split("/");
        const name = parts.pop() ?? "";
        const bus = parts[0] ?? "default";
        return `/events/rule?bus=${q(bus)}&name=${q(name)}`;
      }
      if (kind === "event-bus") return tail === "default" ? "/events" : `/events?bus=${q(tail)}`;
      if (kind === "archive") return `/events/archives?archive=${q(tail)}`;
      if (kind === "api-destination") return `/events/api-destinations`;
      if (kind === "connection") return `/events/connections`;
      return undefined;
    }
    default:
      return undefined;
  }
}

/** The short, readable name of the resource an ARN names. */
export function arnName(arn: string | undefined | null): string {
  const a = parseArn(arn);
  if (!a) return arn ?? "";
  if (a.service === "logs") return a.resource.split(":")[1] ?? a.resource;
  if (a.service === "lambda") return a.resource.split(":").slice(1).join(":");
  if (a.service === "events" && a.resource.startsWith("rule/")) return a.resource.split("/").pop() ?? a.resource;
  if (a.service === "sns" && a.resource.includes(":")) return a.resource.split(":")[0];
  const parts = a.resource.split(/[/:]/);
  return parts[parts.length - 1] || a.resource;
}

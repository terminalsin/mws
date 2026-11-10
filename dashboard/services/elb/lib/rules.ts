// Field rules for the load balancing forms. The model leaves names and
// target IDs unconstrained; these are the rules ELB documents (and MWS
// enforces), so the forms flag them before a round trip.
import type { Rule } from "@mws-dashboard/ui";
import { CreateListener, CreateLoadBalancer, CreateTargetGroup, RegisterTargets } from "@mws-dashboard/ui/model/elbv2";

const NAME = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,30}[A-Za-z0-9])?";

export const LB_NAME: Rule = {
  ...CreateLoadBalancer.Name,
  maxLength: 32,
  pattern: `^${NAME}$`,
  // MWS, like AWS, keeps internal- for internal load balancers' DNS names.
  reserved: ["internal-"],
  hint: "Letters, digits and inner hyphens",
  generate: "name",
};

export const TG_NAME: Rule = { ...CreateTargetGroup.Name, maxLength: 32, pattern: `^${NAME}$`, hint: "Letters, digits and inner hyphens", generate: "name" };

export const HEALTH_PATH: Rule = { ...CreateTargetGroup.HealthCheckPath, pattern: "^/[\\S]*$", hint: "Starts with /" };

export const PORT: Rule = CreateTargetGroup.Port;
export const LISTENER_PORT: Rule = CreateListener.Port;
export const TARGET_PORT: Rule = RegisterTargets.Targets.item?.fields?.Port ?? PORT;

const list = (one: string) => `^${one}(?:[\\s,]+${one})*$`;
const IP = "(?:\\d{1,3}\\.){3}\\d{1,3}";

/** What a target group's targets look like, by target type: one per line
 * or comma separated. */
export function targetsRule(type: string | undefined, arnTemplate: string): Rule {
  switch (type) {
    case "ip":
      return { required: true, pattern: list(IP), hint: "IP addresses, like 10.0.1.10" };
    case "lambda":
      return { required: true, format: "arn", arn: arnTemplate, hint: "A function ARN" };
    case "alb":
      return { required: true, format: "arn", hint: "An Application Load Balancer ARN" };
    default:
      return { required: true, pattern: list("i-[0-9a-f]{8,17}"), hint: "Instance IDs, like i-0123456789abcdef0" };
  }
}

/** Protocols a listener of this load balancer type can forward to, by the
 * target group's protocol (Lambda groups have none). */
export function forwardsTo(lbType: string | undefined, group: { Protocol?: string; TargetType?: string }) {
  if (lbType === "gateway") return group.Protocol === "GENEVE";
  if (lbType === "network") return ["TCP", "TLS", "UDP", "TCP_UDP"].includes(group.Protocol ?? "");
  return group.TargetType === "lambda" || group.Protocol === "HTTP" || group.Protocol === "HTTPS";
}

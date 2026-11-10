import type { Target } from "@aws-sdk/client-eventbridge";
import { AwsIcon, SERVICES } from "@mws-dashboard/ui";
import Link from "next/link";

import { arnHref, arnName } from "./links";

/** The catalog service an ARN belongs to, for its icon. */
export function targetIcon(arn?: string) {
  const service = arn?.split(":")[2];
  const map: Record<string, string> = { sqs: "sqs", sns: "sns", lambda: "lambda", logs: "cloudwatch", events: "events", kinesis: "kinesis", firehose: "firehose", states: "events", ecs: "ecs", ssm: "ssm" };
  const s = SERVICES.find((x) => x.id === map[service ?? ""]);
  return s?.icon ?? "service/AmazonEventBridge";
}

export const ruleHref = (bus: string, name: string) => `/events/rule?bus=${encodeURIComponent(bus)}&name=${encodeURIComponent(name)}`;

/** A rule's targets as icons, linked to their pages unless the row they
 * sit in is a link itself. */
export function TargetIcons({ targets, linked }: { targets: Target[]; linked?: boolean }) {
  return (
    <span className="icon-stack">
      {targets.map((t) => {
        const href = linked ? arnHref(t.Arn) : undefined;
        const icon = <AwsIcon icon={targetIcon(t.Arn)} size={22} label={arnName(t.Arn)} />;
        return href ? (
          <Link key={t.Id} href={href} title={arnName(t.Arn)} aria-label={arnName(t.Arn)}>
            {icon}
          </Link>
        ) : (
          <span key={t.Id} title={t.Arn}>
            {icon}
          </span>
        );
      })}
    </span>
  );
}

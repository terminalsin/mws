import type { Subscription } from "@aws-sdk/client-sns";
import { AwsIcon, Segments } from "@mws-dashboard/ui";
import { Globe, Mail, MessageSquare, Smartphone } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { arnHref, arnName } from "./links";

export function protocolIcon(protocol?: string): ReactNode {
  switch (protocol) {
    case "sqs":
      return <AwsIcon icon="service/AmazonSimpleQueueService" size={24} />;
    case "lambda":
      return <AwsIcon icon="service/AWSLambda" size={24} />;
    case "firehose":
      return <AwsIcon icon="service/AmazonDataFirehose" size={24} />;
    case "email":
    case "email-json":
      return <Mail size={18} aria-hidden />;
    case "sms":
      return <MessageSquare size={18} aria-hidden />;
    case "application":
      return <Smartphone size={18} aria-hidden />;
    default:
      return <Globe size={18} aria-hidden />;
  }
}

/** A subscription's endpoint, linked to its console page when it is a
 * resource (queue, function, stream). */
export function Endpoint({ sub, linked = true }: { sub: Pick<Subscription, "Endpoint" | "Protocol">; linked?: boolean }) {
  const href = linked ? arnHref(sub.Endpoint) : undefined;
  if (href) return <Link href={href}>{arnName(sub.Endpoint)}</Link>;
  return <>{sub.Endpoint?.startsWith("arn:") ? arnName(sub.Endpoint) : sub.Endpoint}</>;
}

export const pending = (s: Pick<Subscription, "SubscriptionArn">) => s.SubscriptionArn === "PendingConfirmation" || s.SubscriptionArn === "pending confirmation";

/** Topics, Subscriptions and Deliveries, as the AWS console's sidebar has them. */
export function SnsTabs({ active }: { active: "topics" | "subscriptions" | "outbox" }) {
  return (
    <Segments
      label="SNS"
      items={[
        { label: "Topics", href: "/sns", active: active === "topics" },
        { label: "Subscriptions", href: "/sns/subscriptions", active: active === "subscriptions" },
        { label: "Deliveries", href: "/sns?tab=outbox", active: active === "outbox" },
      ]}
    />
  );
}

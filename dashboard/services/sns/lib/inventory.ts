import "server-only";

import { ListTopicsCommand } from "@aws-sdk/client-sns";
import { all, shortName, type InventoryItem } from "@mws-dashboard/aws";

import { sns } from "./clients";

export async function topicItems(): Promise<InventoryItem[]> {
  const client = await sns();
  const topics = await all(
    (NextToken) => client.send(new ListTopicsCommand({ NextToken })),
    (r) => r.Topics,
    (r) => r.NextToken,
  );
  return topics.map((t) => ({
    service: "sns",
    type: "Topic",
    id: t.TopicArn!,
    name: shortName(t.TopicArn),
    href: `/sns/topic?arn=${encodeURIComponent(t.TopicArn!)}`,
  }));
}

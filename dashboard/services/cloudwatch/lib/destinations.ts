import "server-only";

import { DescribeDestinationsCommand } from "@aws-sdk/client-cloudwatch-logs";
import {
  FirehoseClient,
  ListDeliveryStreamsCommand,
} from "@aws-sdk/client-firehose";
import { KinesisClient, ListStreamsCommand } from "@aws-sdk/client-kinesis";
import { KMSClient, ListAliasesCommand } from "@aws-sdk/client-kms";
import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { all, client, frameInfo } from "@mws-dashboard/aws";

import { logs } from "./clients";

const safe = async <T>(f: () => Promise<T[]>): Promise<T[]> => {
  try {
    return await f();
  } catch {
    return [];
  }
};

/** Where a subscription filter can send events: Lambda functions, Kinesis
 * and Firehose streams, and Logs destinations, as ARNs. */
export async function subscriptionTargets(): Promise<string[]> {
  const info = await frameInfo();
  const [functions, streams, firehoses, destinations] = await Promise.all([
    safe(async () => {
      const c = await client(LambdaClient);
      return all(
        (Marker) => c.send(new ListFunctionsCommand({ Marker })),
        (r) => r.Functions?.map((f) => f.FunctionArn!),
        (r) => r.NextMarker,
      );
    }),
    safe(async () => {
      const c = await client(KinesisClient);
      return all(
        (NextToken) => c.send(new ListStreamsCommand({ NextToken })),
        (r) => r.StreamSummaries?.map((s) => s.StreamARN!),
        (r) => (r.HasMoreStreams ? r.NextToken : undefined),
      );
    }),
    safe(async () => {
      const c = await client(FirehoseClient);
      const names: string[] = [];
      let start: string | undefined;
      for (;;) {
        const out = await c.send(
          new ListDeliveryStreamsCommand({
            Limit: 10000,
            ExclusiveStartDeliveryStreamName: start,
          }),
        );
        names.push(...(out.DeliveryStreamNames ?? []));
        if (!out.HasMoreDeliveryStreams || !out.DeliveryStreamNames?.length)
          break;
        start = names[names.length - 1];
      }
      return names.map(
        (n) =>
          `arn:aws:firehose:${info.region}:${info.account}:deliverystream/${n}`,
      );
    }),
    safe(async () => {
      const c = await logs();
      return all(
        (nextToken) => c.send(new DescribeDestinationsCommand({ nextToken })),
        (r) => r.destinations?.map((d) => d.arn!),
        (r) => r.nextToken,
      );
    }),
  ]);
  return [...functions, ...streams, ...firehoses, ...destinations];
}

/** KMS keys by alias, for the log group's encryption key. */
export async function keyOptions(): Promise<{
  arns: string[];
  aliases: Record<string, string>;
}> {
  const info = await frameInfo();
  const aliases = await safe(async () => {
    const c = await client(KMSClient);
    return all(
      (Marker) => c.send(new ListAliasesCommand({ Marker })),
      (r) => r.Aliases,
      (r) => (r.Truncated ? r.NextMarker : undefined),
    );
  });
  const mine = aliases.filter(
    (a) => a.TargetKeyId && !a.AliasName?.startsWith("alias/aws/"),
  );
  const arn = (id: string) =>
    `arn:aws:kms:${info.region}:${info.account}:key/${id}`;
  return {
    arns: mine.map((a) => arn(a.TargetKeyId!)),
    aliases: Object.fromEntries(
      mine.map((a) => [a.AliasName!, arn(a.TargetKeyId!)]),
    ),
  };
}

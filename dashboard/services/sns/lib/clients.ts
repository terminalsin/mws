import "server-only";

import { FirehoseClient, ListDeliveryStreamsCommand } from "@aws-sdk/client-firehose";
import { IAMClient, ListRolesCommand } from "@aws-sdk/client-iam";
import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { ListEndpointsByPlatformApplicationCommand, ListPlatformApplicationsCommand, SNSClient } from "@aws-sdk/client-sns";
import { ListQueuesCommand, SQSClient } from "@aws-sdk/client-sqs";
import { client } from "@mws-dashboard/aws";

import type { Scope } from "./rules";
import type { Targets } from "./subscribe";

export const sqs = () => client(SQSClient);
export const sns = () => client(SNSClient);
export const ICONS = {
  topic: "resource/AmazonSimpleNotificationServiceTopic",
};

/** What a subscription can point at, for the endpoint field's suggestions
 * (first page of each; a failed list just suggests nothing). */
export async function targets(scope: Scope): Promise<Targets> {
  const none = (): string[] => [];
  const arn = (service: string, resource: string) => `arn:${scope.partition}:${service}:${scope.region}:${scope.account}:${resource}`;
  const [queues, functions, streams, roles, endpoints] = await Promise.all([
    // A queue URL ends in /<account>/<name>.
    sqs()
      .then((c) => c.send(new ListQueuesCommand({ MaxResults: 1000 })))
      .then((r) => (r.QueueUrls ?? []).map((u) => u.split("/").slice(-2)).map(([account, name]) => `arn:${scope.partition}:sqs:${scope.region}:${account}:${name}`), none),
    client(LambdaClient)
      .then((c) => c.send(new ListFunctionsCommand({})))
      .then((r) => (r.Functions ?? []).map((f) => f.FunctionArn!), none),
    client(FirehoseClient)
      .then((c) => c.send(new ListDeliveryStreamsCommand({ Limit: 1000 })))
      .then((r) => (r.DeliveryStreamNames ?? []).map((n) => arn("firehose", `deliverystream/${n}`)), none),
    client(IAMClient)
      .then((c) => c.send(new ListRolesCommand({ MaxItems: 1000 })))
      .then((r) => (r.Roles ?? []).map((x) => x.Arn!), none),
    sns()
      .then(async (c) => {
        const apps = (await c.send(new ListPlatformApplicationsCommand({}))).PlatformApplications ?? [];
        const lists = await Promise.all(
          apps.slice(0, 10).map((a) => c.send(new ListEndpointsByPlatformApplicationCommand({ PlatformApplicationArn: a.PlatformApplicationArn! }))),
        );
        return lists.flatMap((l) => (l.Endpoints ?? []).map((e) => e.EndpointArn!));
      })
      .catch(none),
  ]);
  return { sqs: queues, lambda: functions, firehose: streams, application: endpoints, roles };
}

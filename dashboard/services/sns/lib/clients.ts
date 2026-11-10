import "server-only";

import { FirehoseClient, ListDeliveryStreamsCommand } from "@aws-sdk/client-firehose";
import { IAMClient, ListRolesCommand } from "@aws-sdk/client-iam";
import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { ListEndpointsByPlatformApplicationCommand, ListPlatformApplicationsCommand, SNSClient } from "@aws-sdk/client-sns";
import { ListQueuesCommand, SQSClient } from "@aws-sdk/client-sqs";
import { all, client, collect } from "@mws-dashboard/aws";

import type { Scope } from "./rules";
import type { Targets } from "./subscribe";

export const sqs = () => client(SQSClient);
export const sns = () => client(SNSClient);
export const lambda = () => client(LambdaClient);
export const ICONS = {
  topic: "resource/AmazonSimpleNotificationServiceTopic",
  email: "resource/AmazonSimpleNotificationServiceEmailNotification",
  http: "resource/AmazonSimpleNotificationServiceHTTPNotification",
};

/** What a subscription can point at, for the endpoint field's suggestions
 * (a failed list just suggests nothing). */
export async function targets(scope: Scope): Promise<Targets> {
  const none = (): string[] => [];
  const arn = (service: string, resource: string) => `arn:${scope.partition}:${service}:${scope.region}:${scope.account}:${resource}`;
  const [queues, functions, streams, roles, endpoints] = await Promise.all([
    // A queue URL ends in /<account>/<name>.
    sqs()
      .then((c) => collect((NextToken) => c.send(new ListQueuesCommand({ MaxResults: 1000, NextToken })), (r) => r.QueueUrls, (r) => r.NextToken, 10_000))
      .then((urls) => urls.map((u) => u.split("/").slice(-2)).map(([account, name]) => `arn:${scope.partition}:sqs:${scope.region}:${account}:${name}`), none),
    lambda()
      .then((c) => all((Marker) => c.send(new ListFunctionsCommand({ Marker })), (r) => r.Functions, (r) => r.NextMarker))
      .then((f) => f.map((x) => x.FunctionArn!), none),
    client(FirehoseClient)
      .then(async (c) => {
        const names: string[] = [];
        let start: string | undefined;
        for (;;) {
          const r = await c.send(new ListDeliveryStreamsCommand({ Limit: 1000, ExclusiveStartDeliveryStreamName: start }));
          names.push(...(r.DeliveryStreamNames ?? []));
          if (!r.HasMoreDeliveryStreams || !r.DeliveryStreamNames?.length) break;
          start = names[names.length - 1];
        }
        return names.map((n) => arn("firehose", `deliverystream/${n}`));
      })
      .catch(none),
    client(IAMClient)
      .then((c) => all((Marker) => c.send(new ListRolesCommand({ Marker })), (r) => r.Roles, (r) => (r.IsTruncated ? r.Marker : undefined)))
      .then((r) => r.map((x) => x.Arn!), none),
    sns()
      .then(async (c) => {
        const apps = await all((NextToken) => c.send(new ListPlatformApplicationsCommand({ NextToken })), (r) => r.PlatformApplications, (r) => r.NextToken);
        const lists = await Promise.all(
          apps.map((a) =>
            all((NextToken) => c.send(new ListEndpointsByPlatformApplicationCommand({ PlatformApplicationArn: a.PlatformApplicationArn!, NextToken })), (r) => r.Endpoints, (r) => r.NextToken),
          ),
        );
        return lists.flat().map((e) => e.EndpointArn!);
      })
      .catch(none),
  ]);
  return { sqs: queues, lambda: functions, firehose: streams, application: endpoints, roles };
}

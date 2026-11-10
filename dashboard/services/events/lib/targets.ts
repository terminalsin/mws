import "server-only";

import { ListApiDestinationsCommand, ListArchivesCommand, ListConnectionsCommand, ListEventBusesCommand } from "@aws-sdk/client-eventbridge";
import { ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { ListTopicsCommand } from "@aws-sdk/client-sns";
import { ListQueuesCommand } from "@aws-sdk/client-sqs";
import { all, collect, region } from "@mws-dashboard/aws";

import { events, lambda, sns, sqs } from "./clients";

/** ARNs a rule can target, for the target field's suggestions. */
export async function targetArns(): Promise<string[]> {
  const none = (): string[] => [];
  const r = await region();
  const [queues, topics, functions, destinations] = await Promise.all([
    sqs()
      .then((c) => collect((NextToken) => c.send(new ListQueuesCommand({ NextToken, MaxResults: 1000 })), (x) => x.QueueUrls, (x) => x.NextToken, 10_000))
      .then((urls) => urls.map((u) => u.split("/").slice(-2)).map(([account, name]) => `arn:aws:sqs:${r}:${account}:${name}`), none),
    sns()
      .then((c) => all((NextToken) => c.send(new ListTopicsCommand({ NextToken })), (x) => x.Topics?.map((t) => t.TopicArn!), (x) => x.NextToken))
      .catch(none),
    lambda()
      .then((c) => all((Marker) => c.send(new ListFunctionsCommand({ Marker })), (x) => x.Functions?.map((f) => f.FunctionArn!), (x) => x.NextMarker))
      .catch(none),
    apiDestinations()
      .then((l) => l.map((d) => d.ApiDestinationArn!))
      .catch(none),
  ]);
  return [...queues, ...topics, ...functions, ...destinations];
}

export async function buses() {
  const client = await events();
  return all((NextToken) => client.send(new ListEventBusesCommand({ NextToken })), (r) => r.EventBuses, (r) => r.NextToken);
}

export async function archives() {
  const client = await events();
  return all((NextToken) => client.send(new ListArchivesCommand({ NextToken })), (r) => r.Archives, (r) => r.NextToken);
}

export async function connections() {
  const client = await events();
  return all((NextToken) => client.send(new ListConnectionsCommand({ NextToken })), (r) => r.Connections, (r) => r.NextToken);
}

export async function apiDestinations() {
  const client = await events();
  return all((NextToken) => client.send(new ListApiDestinationsCommand({ NextToken })), (r) => r.ApiDestinations, (r) => r.NextToken);
}

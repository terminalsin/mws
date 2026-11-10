import "server-only";

import { ListDeliveryStreamsCommand, FirehoseClient } from "@aws-sdk/client-firehose";
import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { ListBucketsCommand, S3Client } from "@aws-sdk/client-s3";
import { ListConfigurationSetsCommand, ListEmailTemplatesCommand } from "@aws-sdk/client-sesv2";
import { ListTopicsCommand, SNSClient } from "@aws-sdk/client-sns";
import { all, client, frameInfo } from "@mws-dashboard/aws";

import { ses } from "./clients";

const quietly = <T,>(read: () => Promise<T>, fallback: T) => read().catch(() => fallback);

export const topics = () =>
  quietly(async () => {
    const sns = await client(SNSClient);
    return (await all((NextToken) => sns.send(new ListTopicsCommand({ NextToken })), (r) => r.Topics, (r) => r.NextToken)).map((t) => t.TopicArn!);
  }, [] as string[]);

export const buckets = () => quietly(async () => ((await (await client(S3Client, { forcePathStyle: true })).send(new ListBucketsCommand({}))).Buckets ?? []).map((b) => b.Name!), [] as string[]);

export const functions = () =>
  quietly(async () => {
    const lambda = await client(LambdaClient);
    return (await all((Marker) => lambda.send(new ListFunctionsCommand({ Marker })), (r) => r.Functions, (r) => r.NextMarker)).map((f) => f.FunctionArn!);
  }, [] as string[]);

export const streams = () =>
  quietly(async () => {
    const [{ account, region }, out] = await Promise.all([frameInfo(), (await client(FirehoseClient)).send(new ListDeliveryStreamsCommand({ Limit: 100 }))]);
    return (out.DeliveryStreamNames ?? []).map((n) => `arn:aws:firehose:${region}:${account}:deliverystream/${n}`);
  }, [] as string[]);

export const configSets = () =>
  quietly(async () => {
    const c = await ses();
    return all((NextToken) => c.send(new ListConfigurationSetsCommand({ NextToken })), (r) => r.ConfigurationSets, (r) => r.NextToken);
  }, [] as string[]);

export const templates = () =>
  quietly(async () => {
    const c = await ses();
    return all((NextToken) => c.send(new ListEmailTemplatesCommand({ NextToken })), (r) => r.TemplatesMetadata, (r) => r.NextToken);
  }, []);

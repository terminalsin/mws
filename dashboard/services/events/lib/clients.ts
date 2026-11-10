import "server-only";

import { CloudWatchLogsClient } from "@aws-sdk/client-cloudwatch-logs";
import { EventBridgeClient } from "@aws-sdk/client-eventbridge";
import { LambdaClient } from "@aws-sdk/client-lambda";
import { SNSClient } from "@aws-sdk/client-sns";
import { SQSClient } from "@aws-sdk/client-sqs";
import { client } from "@mws-dashboard/aws";

export const events = () => client(EventBridgeClient);
export const sqs = () => client(SQSClient);
export const sns = () => client(SNSClient);
export const lambda = () => client(LambdaClient);
export const logs = () => client(CloudWatchLogsClient);

export const ICONS = {
  rule: "resource/AmazonEventBridgeRule",
  bus: "resource/AmazonEventBridgeCustomEventBus",
  defaultBus: "resource/AmazonEventBridgeDefaultEventBus",
  event: "resource/AmazonEventBridgeEvent",
  partner: "resource/AmazonEventBridgeSaasPartnerEvent",
};

/** Rules EventBridge itself manages (an archive's `Events-Archive-*`): only
 * their owner may change them. */
export const managed = (rule: { ManagedBy?: string }) => !!rule.ManagedBy;

/** A rule is enabled in either of its enabled states. */
export const enabled = (state?: string) => state === "ENABLED" || state === "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS";

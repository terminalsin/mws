import "server-only";

import { SESClient } from "@aws-sdk/client-ses";
import { SESv2Client } from "@aws-sdk/client-sesv2";
import { client } from "@mws-dashboard/aws";

export const ses = () => client(SESv2Client);
/** SES v1: receipt rules and filters, verification tokens and notification topics exist only there. */
export const sesV1 = () => client(SESClient);

export const ICONS = {
  email: "resource/AmazonSimpleEmailServiceEmail",
  notification: "resource/AmazonSimpleNotificationServiceEmailNotification",
  topic: "resource/AmazonSimpleNotificationServiceTopic",
  zone: "resource/AmazonRoute53HostedZone",
  lambda: "service/AWSLambda",
  s3: "service/AmazonSimpleStorageService",
  sns: "service/AmazonSimpleNotificationService",
  events: "service/AmazonEventBridge",
  firehose: "service/AmazonDataFirehose",
  cloudwatch: "service/AmazonCloudWatch",
};

export const identityHref = (name: string | undefined) => `/ses/identity?name=${encodeURIComponent(name ?? "")}`;
export const configSetHref = (name: string | undefined) => `/ses/configset?name=${encodeURIComponent(name ?? "")}`;
export const templateHref = (name: string | undefined) => `/ses/template?name=${encodeURIComponent(name ?? "")}`;
export const ruleSetHref = (name: string | undefined) => `/ses/ruleset?name=${encodeURIComponent(name ?? "")}`;

/** Verification status as the console tones it: FAILED is final (a pending
 * identity fails after 24 or 72 hours), TEMPORARY_FAILURE may recover. */
export const VERIFICATION_TONE: Record<string, "good" | "warn" | "bad" | "neutral"> = {
  SUCCESS: "good",
  PENDING: "warn",
  TEMPORARY_FAILURE: "warn",
  FAILED: "bad",
  NOT_STARTED: "neutral",
};
export const verificationLabel = (s: string | undefined) => (s === "SUCCESS" ? "verified" : (s?.toLowerCase().replace("_", " ") ?? "pending"));

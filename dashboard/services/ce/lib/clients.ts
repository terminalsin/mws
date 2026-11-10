import "server-only";

import { CostExplorerClient } from "@aws-sdk/client-cost-explorer";
import { SNSClient } from "@aws-sdk/client-sns";
import { client } from "@mws-dashboard/aws";

export const ce = () => client(CostExplorerClient);
/** Anomaly alerts publish to SNS topics. */
export const sns = () => client(SNSClient);

export const ICONS = {
  ce: "service/AWSCostExplorer",
  monitor: "resource/AWSTrustedAdvisorChecklistCost",
  subscription: "resource/Alert",
  email: "resource/Email",
  topic: "resource/AmazonSimpleNotificationServiceTopic",
  category: "service/AWSCostandUsageReport",
};

import "server-only";

import { EventBridgeClient } from "@aws-sdk/client-eventbridge";
import { client } from "@mws-dashboard/aws";

export const events = () => client(EventBridgeClient);

export const ICONS = {
  rule: "resource/AmazonEventBridgeRule",
  bus: "resource/AmazonEventBridgeCustomEventBus",
};

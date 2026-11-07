import "server-only";

import { CloudWatchClient } from "@aws-sdk/client-cloudwatch";
import { CloudWatchLogsClient } from "@aws-sdk/client-cloudwatch-logs";
import { client } from "@mws-dashboard/aws";

export const logs = () => client(CloudWatchLogsClient);
export const cloudwatch = () => client(CloudWatchClient);

export const groupHref = (name: string, extra: Record<string, string> = {}) =>
  `/logs/group?${new URLSearchParams({ name, ...extra })}`;

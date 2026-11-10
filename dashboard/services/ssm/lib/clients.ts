import "server-only";

import { SSMClient } from "@aws-sdk/client-ssm";
import { client } from "@mws-dashboard/aws";

export const ssm = () => client(SSMClient);

export const ICONS = {
  ssm: "service/AWSSystemsManager",
  parameter: "resource/AWSSystemsManagerParameterStore",
  node: "resource/AmazonEC2Instance",
  runCommand: "resource/AWSSystemsManagerRunCommand",
  document: "resource/AWSSystemsManagerDocuments",
  automation: "resource/AWSSystemsManagerAutomation",
  association: "resource/AWSSystemsManagerStateManager",
  window: "resource/AWSSystemsManagerMaintenanceWindows",
  session: "resource/AWSSystemsManagerSessionManager",
  opsItem: "resource/AWSSystemsManagerOpsCenter",
  calendar: "resource/AWSSystemsManagerChangeCalendar",
};

import "server-only";

import { SSMClient } from "@aws-sdk/client-ssm";
import { client } from "@mws-dashboard/aws";

export const ssm = () => client(SSMClient);

export const ICONS = {
  ssm: "service/AWSSystemsManager",
  parameter: "resource/AWSSystemsManagerParameterStore",
};

import "server-only";

import { CloudTrailClient } from "@aws-sdk/client-cloudtrail";
import { client } from "@mws-dashboard/aws";

export const cloudtrail = () => client(CloudTrailClient);

export const ICONS = {
  cloudtrail: "service/AWSCloudTrail",
};

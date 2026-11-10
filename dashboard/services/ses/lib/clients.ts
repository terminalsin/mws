import "server-only";

import { SESv2Client } from "@aws-sdk/client-sesv2";
import { client } from "@mws-dashboard/aws";

export const ses = () => client(SESv2Client);

export const ICONS = {
  email: "resource/AmazonSimpleEmailServiceEmail",
};

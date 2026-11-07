import "server-only";

import { EC2Client } from "@aws-sdk/client-ec2";
import { LambdaClient } from "@aws-sdk/client-lambda";
import { client } from "@mws-dashboard/aws";

export const lambda = () => client(LambdaClient);
export const ec2 = () => client(EC2Client);

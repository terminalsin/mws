import "server-only";

import { EC2Client } from "@aws-sdk/client-ec2";
import { client } from "@mws-dashboard/aws";

export const ec2 = () => client(EC2Client);

export const ICONS = {
  instance: "resource/AmazonEC2Instance",
  ami: "resource/AmazonEC2AMI",
  sg: "resource/AmazonVPCNetworkAccessControlList",
  key: "resource/AWSIdentityAccessManagementDataEncryptionKey",
};

export const nameTag = (i: { Tags?: { Key?: string; Value?: string }[] }) => i.Tags?.find((t) => t.Key === "Name")?.Value;

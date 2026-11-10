import "server-only";

import { EC2Client } from "@aws-sdk/client-ec2";
import { IAMClient } from "@aws-sdk/client-iam";
import { client } from "@mws-dashboard/aws";

/** An EC2 client for the selected region, or for `region` (cross-region copies). */
export const ec2 = (region?: string) => client(EC2Client, region ? { region } : {});
export const iam = () => client(IAMClient);

export const ICONS = {
  instance: "resource/AmazonEC2Instance",
  ami: "resource/AmazonEC2AMI",
  sg: "resource/AmazonVPCNetworkAccessControlList",
  key: "resource/AWSIdentityAccessManagementDataEncryptionKey",
  volume: "resource/AmazonElasticBlockStoreVolume",
  snapshot: "resource/AmazonElasticBlockStoreSnapshot",
  template: "resource/AmazonEC2Instances",
  eni: "resource/AmazonVPCElasticNetworkInterface",
  role: "resource/AWSIdentityAccessManagementRole",
};

export const nameTag = (i: { Tags?: { Key?: string; Value?: string }[] }) => i.Tags?.find((t) => t.Key === "Name")?.Value;

/** Console URLs of related resources (VPC pages belong to the vpc package). */
export const LINKS = {
  instance: (id: string) => `/ec2/instance?id=${encodeURIComponent(id)}`,
  volume: (id: string) => `/ec2/volume?id=${encodeURIComponent(id)}`,
  image: (id: string) => `/ec2/image?id=${encodeURIComponent(id)}`,
  group: (id: string) => `/ec2/group?id=${encodeURIComponent(id)}`,
  template: (id: string) => `/ec2/launch-template?id=${encodeURIComponent(id)}`,
  vpc: (id: string) => `/vpc/${encodeURIComponent(id)}`,
  subnet: (id: string) => `/vpc/subnet?id=${encodeURIComponent(id)}`,
  instanceProfile: (name: string) => `/iam/instance-profiles/${encodeURIComponent(name)}`,
  kms: (key: string) => `/kms/key?id=${encodeURIComponent(key)}`,
};

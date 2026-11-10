import "server-only";

import { EC2Client } from "@aws-sdk/client-ec2";
import { IAMClient } from "@aws-sdk/client-iam";
import { ImagebuilderClient } from "@aws-sdk/client-imagebuilder";
import { client } from "@mws-dashboard/aws";

export const imagebuilder = () => client(ImagebuilderClient);

export const ICONS = {
  imagebuilder: "service/AmazonEC2ImageBuilder",
  ami: "resource/AmazonEC2AMI",
  instance: "resource/AmazonEC2Instance",
};

export type Tone = "good" | "warn" | "bad" | "neutral" | "info";

/** Words AWS uses for states, as tones. */
export function tone(status: string | undefined): Tone {
  const s = (status ?? "").toUpperCase();
  if (/FAIL|ERROR|CANCEL|UNHEALTHY|DEPRECATED|DELETED/.test(s)) return "bad";
  if (/PENDING|RUNNING|PROVISION|BUILD|CREAT|UPDAT|DELET|PROGRESS|TEST|DISTRIBUT|INTEGRAT|STARTING|CANCELLING|LEGACY/.test(s)) return "warn";
  if (/SUCCE|AVAILABLE|ACTIVE|HEALTHY|INSERVICE|COMPLETE|ENABLED|READY/.test(s)) return "good";
  return "neutral";
}
export const iam = () => client(IAMClient);
export const ec2 = () => client(EC2Client);

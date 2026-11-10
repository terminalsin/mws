import "server-only";

import { AutoScalingClient } from "@aws-sdk/client-auto-scaling";
import { EC2Client } from "@aws-sdk/client-ec2";
import { client } from "@mws-dashboard/aws";

export const autoscaling = () => client(AutoScalingClient);
export const ec2 = () => client(EC2Client);

export const ICONS = {
  instance: "resource/AmazonEC2Instance",
  autoscaling: "service/AmazonEC2AutoScaling",
  asg: "resource/AmazonEC2AutoScaling",
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

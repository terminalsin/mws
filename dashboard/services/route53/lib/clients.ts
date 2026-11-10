import "server-only";

import { CloudWatchLogsClient } from "@aws-sdk/client-cloudwatch-logs";
import { EC2Client } from "@aws-sdk/client-ec2";
import { ElasticLoadBalancingV2Client } from "@aws-sdk/client-elastic-load-balancing-v2";
import { GlobalAcceleratorClient } from "@aws-sdk/client-global-accelerator";
import { KMSClient } from "@aws-sdk/client-kms";
import { Route53Client } from "@aws-sdk/client-route-53";
import { client } from "@mws-dashboard/aws";

export const ec2 = () => client(EC2Client);
export const route53 = () => client(Route53Client);
export const elbv2 = () => client(ElasticLoadBalancingV2Client);
export const ga = () => client(GlobalAcceleratorClient);
// Route 53 keeps DNSSEC keys and query logs in us-east-1, whatever the
// console's Region.
export const kmsUsEast1 = () => client(KMSClient, { region: "us-east-1" });
export const logsUsEast1 = () => client(CloudWatchLogsClient, { region: "us-east-1" });

export const ICONS = {
  vpc: "resource/AmazonVPCVirtualprivatecloudVPC",
  zone: "resource/AmazonRoute53HostedZone",
  route53: "service/AmazonRoute53",
  internet: "resource/Internet",
  health: "resource/AmazonRoute53ReadinessChecks",
};

export const nameTag = (r: { Tags?: { Key?: string; Value?: string }[] }) => r.Tags?.find((t) => t.Key === "Name")?.Value;

/** A zone or health check id without its /hostedzone/ prefix. */
export const bareId = (id: string | undefined) => (id ?? "").split("/").pop() ?? "";

export const zoneHref = (id: string | undefined) => `/route53/zone?id=${encodeURIComponent(bareId(id))}`;
export const healthHref = (id: string | undefined) => `/route53/health?id=${encodeURIComponent(id ?? "")}`;

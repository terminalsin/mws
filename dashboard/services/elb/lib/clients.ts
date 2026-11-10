import "server-only";

import { ACMClient } from "@aws-sdk/client-acm";
import { EC2Client } from "@aws-sdk/client-ec2";
import { ElasticLoadBalancingClient } from "@aws-sdk/client-elastic-load-balancing";
import { ElasticLoadBalancingV2Client } from "@aws-sdk/client-elastic-load-balancing-v2";
import { S3Client } from "@aws-sdk/client-s3";
import { client } from "@mws-dashboard/aws";

export const ec2 = () => client(EC2Client);
export const elb = () => client(ElasticLoadBalancingV2Client);
export const acm = () => client(ACMClient);
export const classic = () => client(ElasticLoadBalancingClient);
export const s3 = () => client(S3Client, { forcePathStyle: true });

export const ICONS = {
  vpc: "resource/AmazonVPCVirtualprivatecloudVPC",
  publicSubnet: "group/Publicsubnet",
  eni: "resource/AmazonVPCElasticNetworkInterface",
  alb: "resource/ElasticLoadBalancingApplicationLoadBalancer",
  nlb: "resource/ElasticLoadBalancingNetworkLoadBalancer",
  gwlb: "resource/ElasticLoadBalancingGatewayLoadBalancer",
  elb: "service/ElasticLoadBalancing",
  classic: "resource/ElasticLoadBalancingClassicLoadBalancer",
  trust: "resource/AWSCertificateManagerCertificateAuthority",
  sg: "resource/AmazonVPCNetworkAccessControlList",
  instance: "resource/AmazonEC2Instance",
};

export const LB_ICON: Record<string, string> = { application: ICONS.alb, network: ICONS.nlb, gateway: ICONS.gwlb };

export const nameTag = (r: { Tags?: { Key?: string; Value?: string }[] }) => r.Tags?.find((t) => t.Key === "Name")?.Value;

/** A target group's icon, by what it sends traffic to. */
export const TARGET_ICON: Record<string, string> = {
  instance: "resource/AmazonEC2Instance",
  ip: ICONS.eni,
  lambda: "resource/AWSLambdaLambdaFunction",
  alb: ICONS.alb,
};

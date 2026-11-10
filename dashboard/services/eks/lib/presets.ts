// Starting points for EKS forms, and the logos of well-known add-ons.
// Plain data, shared by server and client components.

export interface NodePreset {
  id: string;
  label: string;
  icon: string;
  title: string;
  type: string;
  amiType: string;
  spot?: boolean;
  desired: number;
  max: number;
}

export const NODE_PRESETS: NodePreset[] = [
  { id: "general", label: "General", icon: "resource/AmazonEC2Instances", title: "t3.medium, on demand", type: "t3.medium", amiType: "AL2023_x86_64_STANDARD", desired: 2, max: 3 },
  { id: "spot", label: "Spot", icon: "resource/AmazonEC2SpotInstance", title: "t3.large, Spot capacity", type: "t3.large", amiType: "AL2023_x86_64_STANDARD", spot: true, desired: 2, max: 5 },
  { id: "graviton", label: "Graviton", icon: "brand/arm", title: "m7g.large, Arm", type: "m7g.large", amiType: "AL2023_ARM_64_STANDARD", desired: 2, max: 3 },
  { id: "gpu", label: "GPU", icon: "brand/nvidia", title: "g5.xlarge, NVIDIA", type: "g5.xlarge", amiType: "AL2023_x86_64_NVIDIA", desired: 1, max: 2 },
];

const ADDON_ICONS: Record<string, string> = {
  "vpc-cni": "resource/AmazonVPCElasticNetworkInterface",
  coredns: "service/AmazonRoute53",
  "kube-proxy": "brand/kubernetes",
  "aws-ebs-csi-driver": "service/AmazonElasticBlockStore",
  "aws-efs-csi-driver": "service/AmazonEFS",
  "aws-mountpoint-s3-csi-driver": "service/AmazonSimpleStorageService",
  "snapshot-controller": "resource/AmazonElasticBlockStoreSnapshot",
  "eks-pod-identity-agent": "resource/AWSIdentityAccessManagementRole",
  "amazon-cloudwatch-observability": "service/AmazonCloudWatch",
  adot: "service/AWSDistroforOpenTelemetry",
  "aws-guardduty-agent": "service/AmazonGuardDuty",
  "metrics-server": "brand/kubernetes",
  "eks-node-monitoring-agent": "service/AmazonCloudWatch",
};

/** A well-known add-on's logo, else undefined. */
export const addonIcon = (name: string | undefined) => (name ? ADDON_ICONS[name] : undefined);

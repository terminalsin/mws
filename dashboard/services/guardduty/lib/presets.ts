// Suppression rule presets: the findings people most often silence, each a
// finding type and the resource it is about. Shared by the server pages and
// the client fields (no server-only imports).

export interface SuppressionPreset {
  id: string;
  label: string;
  icon: string;
  /** Finding types, comma separated as the field takes them. */
  type: string;
  resource?: string;
  severity?: string;
}

export const SUPPRESSION_PRESETS: SuppressionPreset[] = [
  { id: "port-probes", label: "Port probes", icon: "resource/AmazonVPCInternetGateway", type: "Recon:EC2/PortProbeUnprotectedPort", resource: "Instance" },
  { id: "port-scans", label: "Port scans", icon: "resource/AmazonVPCNetworkAccessAnalyzer", type: "Recon:EC2/Portscan", resource: "Instance" },
  { id: "ssh-brute-force", label: "SSH brute force", icon: "brand/linux", type: "UnauthorizedAccess:EC2/SSHBruteForce", resource: "Instance" },
  { id: "rdp-brute-force", label: "RDP brute force", icon: "resource/AmazonEC2Instance", type: "UnauthorizedAccess:EC2/RDPBruteForce", resource: "Instance" },
  { id: "tor", label: "Tor", icon: "brand/torproject", type: "UnauthorizedAccess:EC2/TorClient, UnauthorizedAccess:EC2/TorRelay", resource: "Instance" },
  { id: "crypto-mining", label: "Crypto mining", icon: "brand/bitcoin", type: "CryptoCurrency:EC2/BitcoinTool.B, CryptoCurrency:EC2/BitcoinTool.B!DNS", resource: "Instance" },
  { id: "root-usage", label: "Root usage", icon: "resource/AWSIdentityAccessManagementLongTermSecurityCredential", type: "Policy:IAMUser/RootCredentialUsage", resource: "AccessKey" },
  { id: "s3-public-access", label: "S3 public access", icon: "resource/AmazonSimpleStorageServiceBucket", type: "Policy:S3/BucketBlockPublicAccessDisabled, Policy:S3/BucketAnonymousAccessGranted", resource: "S3Bucket" },
  { id: "dns-firewall", label: "DNS lookups", icon: "resource/AmazonRoute53ResolverDNSFirewall", type: "Trojan:EC2/DNSDataExfiltration, Backdoor:EC2/C&CActivity.B!DNS", resource: "Instance" },
];

/** A rule name from a finding type: `Recon:EC2/Portscan` → `recon-ec2-portscan`. */
export function nameFromType(type: string) {
  return (
    type
      .split(",")[0]
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 50) || "suppress"
  );
}

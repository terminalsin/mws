// Operating systems and instance sizes the launch form offers as tiles.
// Plain data, shared by server views and the client launch fields.

export interface OsFamily {
  id: string;
  label: string;
  icon: string;
  /** Matches the AMI names (or platform details) of this family's general-purpose images. */
  match: RegExp;
}

export const OS_FAMILIES: OsFamily[] = [
  { id: "amazon-linux", label: "Amazon Linux", icon: "ai/aws-color", match: /^al2023-ami-2023|^amzn2-ami-hvm|amazon linux/i },
  { id: "ubuntu", label: "Ubuntu", icon: "brand/ubuntu", match: /ubuntu/i },
  { id: "debian", label: "Debian", icon: "brand/debian", match: /debian/i },
  { id: "alpine", label: "Alpine", icon: "brand/alpinelinux", match: /alpine/i },
  { id: "rhel", label: "Red Hat", icon: "brand/redhat", match: /rhel|red hat/i },
  { id: "suse", label: "SUSE", icon: "brand/suse", match: /suse/i },
  { id: "fedora", label: "Fedora", icon: "brand/fedora", match: /fedora/i },
  { id: "rocky", label: "Rocky Linux", icon: "brand/rockylinux", match: /rocky/i },
];

/** The OS logo for an image, from its platform details or name. */
export function osLogo(text: string | undefined): string | undefined {
  const t = text ?? "";
  if (/al2023|amzn|amazon linux|eks-node|ecs/i.test(t)) return "ai/aws-color";
  return OS_FAMILIES.find((f) => f.match.test(t))?.icon ?? (/linux/i.test(t) ? "brand/linux" : undefined);
}

const version = (name: string) => parseFloat(name.match(/(\d+(?:\.\d+)?)/)?.[1] ?? "0");

/** The image a family's tile launches: the newest x86_64 general-purpose one. */
export function familyImage<I extends { id: string; name?: string; arch?: string }>(family: OsFamily, images: I[]): I | undefined {
  const fit = images.filter((i) => i.name && family.match.test(i.name) && !/minimal|ecs|eks/i.test(i.name));
  return fit.sort((a, b) => Number(b.arch === "x86_64") - Number(a.arch === "x86_64") || version(b.name!) - version(a.name!))[0];
}

export interface Size {
  type: string;
  label: string;
  vcpu: number;
  mem: string;
}

/** The burstable sizes most launches pick, smallest first. */
export const SIZES: Size[] = [
  { type: "t3.nano", label: "Nano", vcpu: 2, mem: "0.5 GiB" },
  { type: "t3.micro", label: "Micro", vcpu: 2, mem: "1 GiB" },
  { type: "t3.small", label: "Small", vcpu: 2, mem: "2 GiB" },
  { type: "t3.medium", label: "Medium", vcpu: 2, mem: "4 GiB" },
  { type: "t3.large", label: "Large", vcpu: 2, mem: "8 GiB" },
  { type: "m7i.large", label: "General", vcpu: 2, mem: "8 GiB" },
];

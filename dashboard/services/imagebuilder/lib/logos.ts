// Logos and short labels for Image Builder images and components. Plain
// data, shared by the server pages and the client fields.

/** The OS logo for an image, from its name, OS version or parent. */
export function osLogo(text: string | undefined): string {
  const t = text ?? "";
  if (/ubuntu/i.test(t)) return "brand/ubuntu";
  if (/debian/i.test(t)) return "brand/debian";
  if (/alpine/i.test(t)) return "brand/alpinelinux";
  if (/red ?hat|rhel/i.test(t)) return "brand/redhat";
  if (/suse/i.test(t)) return "brand/suse";
  if (/amazon[- ]linux|al2023|amzn/i.test(t)) return "ai/aws-color";
  if (/windows/i.test(t)) return "resource/AmazonEC2AMI";
  return "brand/linux";
}

/** "amazon-linux-2023-x86" → "Amazon Linux 2023", "ubuntu-server-24-lts-x86" → "Ubuntu 24 LTS". */
export function imageLabel(name: string): string {
  const arch = /-arm64$/.test(name) ? " Arm" : "";
  const base = name
    .replace(/-(x86|x86_64|arm64)$/, "")
    .replace(/^amazon-linux-/, "Amazon Linux ")
    .replace(/^ubuntu-server-/, "Ubuntu ")
    .replace(/-lts$/, " LTS");
  return `${base}${arch}`;
}

/** A component's logo, from what its name says it installs. */
export function componentIcon(name: string): string {
  const n = name.toLowerCase();
  if (n.includes("docker")) return "brand/docker";
  if (n.includes("python")) return "brand/python";
  if (n.includes("nginx")) return "brand/nginx";
  if (n.includes("node")) return "brand/nodedotjs";
  if (n.includes("git")) return "brand/git";
  if (n.includes("cloudwatch")) return "service/AmazonCloudWatch";
  if (n.includes("aws-cli")) return "ai/aws-color";
  if (n.includes("reboot") || n.includes("update")) return "brand/linux";
  if (n.includes("test")) return "brand/gnubash";
  return "brand/gnubash";
}

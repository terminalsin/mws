import "server-only";

import { ago, load } from "@mws-dashboard/aws";
import { AwsIcon, Empty, ErrorNotice, List, Pill, Segments, Status, runtimeIcon } from "@mws-dashboard/ui";
import { ShieldCheck } from "lucide-react";

import { ICONS, LINKS } from "../clients";
import { RESOURCE_TONE, listImages } from "../ec2";

/** The OS logo for an image, from its platform details or name. */
export function osIcon(text: string | undefined) {
  const t = (text ?? "").toLowerCase();
  const brand = [
    ["ubuntu", "brand/ubuntu"],
    ["debian", "brand/debian"],
    ["red hat", "brand/redhat"],
    ["rhel", "brand/redhat"],
    ["suse", "brand/suse"],
    ["alpine", "brand/alpinelinux"],
    ["amazon linux", "brand/linux"],
    ["al2", "brand/linux"],
    ["linux", "brand/linux"],
  ].find(([k]) => t.includes(k))?.[1];
  return brand ?? runtimeIcon(t) ?? ICONS.ami;
}

const OWNERS = [
  { id: "self", label: "Owned by me" },
  { id: "amazon", label: "Amazon" },
];

/** AMIs, "Owned by me" first as in AWS's console; Amazon's catalogue on its own tab. */
export async function ImagesView({ owner }: { owner: string }) {
  const own = owner === "amazon" ? "amazon" : "self";
  const images = await load(() => listImages([own]));
  const now = Date.now();
  const body = (
    <>
      <Segments label="Owner" items={OWNERS.map((o) => ({ label: o.label, href: o.id === "self" ? "/ec2?tab=images" : `/ec2?tab=images&owner=${o.id}`, active: o.id === own }))} />
      {images.ok ? (
        <List
          label="Images"
          empty={<Empty icon={ICONS.ami} />}
          rows={images.value
            .sort((a, b) => (b.CreationDate ?? "").localeCompare(a.CreationDate ?? ""))
            .map((i) => {
              const deprecated = i.DeprecationTime && new Date(i.DeprecationTime).getTime() <= now;
              return {
                key: i.ImageId!,
                icon: <AwsIcon icon={osIcon(`${i.PlatformDetails} ${i.Name}`)} size={22} />,
                title: i.Name ?? i.ImageId,
                subtitle: [i.ImageId, i.Description].filter(Boolean).join(" · "),
                href: LINKS.image(i.ImageId!),
                meta: (
                  <>
                    {i.State && i.State !== "available" && <Status tone={RESOURCE_TONE[i.State] ?? "neutral"}>{i.State}</Status>}
                    {deprecated && <Pill tone="warn">deprecated</Pill>}
                    {i.DeregistrationProtection?.startsWith("enabled") && <ShieldCheck size={15} aria-label="Deregistration protection" />}
                    <Pill>{i.Architecture}</Pill>
                    {own === "self" && <Pill tone={i.Public ? "warn" : "info"}>{i.Public ? "public" : "private"}</Pill>}
                    <span>{ago(i.CreationDate)}</span>
                  </>
                ),
              };
            })}
        />
      ) : (
        <ErrorNotice error={images.error} />
      )}
    </>
  );
  return { body };
}

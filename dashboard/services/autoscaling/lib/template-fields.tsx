"use client";

// "Create launch template" opens on the operating systems: each tile picks
// the newest general-purpose image of its family. Sizes are tiles too; any
// other image or type is still one field away.

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import type { Rule } from "@mws-dashboard/ui";
import { MoreFields, PresetGallery, type PresetItem } from "@mws-dashboard/ui/presets";
import { useMemo, useState } from "react";

export interface ImageOption {
  id: string;
  name?: string;
  arch?: string;
}

const FAMILIES = [
  { id: "amazon-linux", label: "Amazon Linux", icon: "ai/aws-color", match: /^al2023-ami-2023|^amzn2-ami-hvm|amazon linux/i },
  { id: "ubuntu", label: "Ubuntu", icon: "brand/ubuntu", match: /ubuntu/i },
  { id: "debian", label: "Debian", icon: "brand/debian", match: /debian/i },
  { id: "alpine", label: "Alpine", icon: "brand/alpinelinux", match: /alpine/i },
  { id: "rhel", label: "Red Hat", icon: "brand/redhat", match: /rhel|red hat/i },
  { id: "suse", label: "SUSE", icon: "brand/suse", match: /suse/i },
];

const SIZES: PresetItem[] = [
  ["t3.nano", "0.5 GiB"],
  ["t3.micro", "1 GiB"],
  ["t3.small", "2 GiB"],
  ["t3.medium", "4 GiB"],
  ["t3.large", "8 GiB"],
  ["m7i.large", "8 GiB"],
].map(([type, mem]) => ({ id: type, label: type, title: `${type} · 2 vCPU · ${mem}`, icon: <b className="text-sm font-semibold">{mem}</b> }));

const version = (name: string) => parseFloat(name.match(/(\d+(?:\.\d+)?)/)?.[1] ?? "0");

export function TemplateFields({ images, nameRule, typeRule, taken }: { images: ImageOption[]; nameRule: Rule; typeRule?: Rule; taken: string[] }) {
  const tiles = useMemo(
    () =>
      FAMILIES.flatMap((f) => {
        const fit = images.filter((i) => i.name && f.match.test(i.name) && !/minimal|ecs|eks/i.test(i.name));
        const best = fit.sort((a, b) => Number(b.arch === "x86_64") - Number(a.arch === "x86_64") || version(b.name!) - version(a.name!))[0];
        return best ? [{ id: f.id, label: f.label, icon: f.icon, title: best.name, image: best.id }] : [];
      }),
    [images],
  );
  const [image, setImage] = useState(tiles[0]?.image ?? images[0]?.id ?? "");
  const [type, setType] = useState("t3.micro");
  return (
    <>
      {tiles.length > 0 && <PresetGallery presets={tiles} chosen={tiles.find((t) => t.image === image)?.id} choose={(t) => setImage(t.image)} label="Image" testId="template-os" />}
      <Field label="Name" rule={nameRule} taken={taken} unique>
        <input name="name" required autoFocus />
      </Field>
      <PresetGallery presets={SIZES} chosen={type} choose={(t) => setType(t.id)} label="Size" testId="template-size" />
      <Field label="Instance type" rule={typeRule} member="LaunchTemplateData.InstanceType">
        <input name="type" value={type} onChange={(e) => setType(e.target.value)} />
      </Field>
      <MoreFields label="Other image">
        <Field label="Image" member="LaunchTemplateData.ImageId">
          <select name="image" value={image} onChange={(e) => setImage(e.target.value)}>
            {images.map((i) => (
              <option key={i.id} value={i.id}>
                {i.name ?? i.id}
              </option>
            ))}
          </select>
        </Field>
      </MoreFields>
    </>
  );
}

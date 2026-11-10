"use client";

// The create-share form opens on what this account can share: picking a CA
// fills its ARN and a name, and the principals start at the organization,
// so sharing a CA with it is one click and Create.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { CreateResourceShare } from "@mws-dashboard/ui/model/ram";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import { Wrench } from "lucide-react";
import { useState, type ReactNode } from "react";

import { shareRules } from "./rules";

type Targets = Parameters<typeof shareRules>[0];

const slug = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 40) || "share";

export function ShareFields({ targets, names, orgSharing, children }: { targets: NonNullable<Targets>; names: string[]; orgSharing: boolean; children?: ReactNode }) {
  const rules = shareRules(targets);
  const other = { id: "other", label: "Other", icon: <Wrench size={22} aria-hidden /> };
  const tiles = targets.cas.map((c) => ({ id: c.arn, label: c.name, title: c.arn, icon: "resource/AWSCertificateManagerCertificateAuthority" }));
  const [chosen, setChosen] = useState(tiles[0]?.id ?? other.id);
  const ca = targets.cas.find((c) => c.arn === chosen);
  // With organization sharing on, sharing with all of it is the usual intent.
  const org = orgSharing ? targets.principals.find((p) => p.includes(":organization/")) : undefined;
  return (
    <>
      {tiles.length > 0 && <PresetGallery label="Resource" presets={[...tiles, other]} chosen={chosen} choose={(t) => setChosen(t.id)} testId="share-resource" />}
      <div key={chosen} className="preset-fields">
        <FieldShell label="Name" rule={{ ...CreateResourceShare.name, generate: "name" }}>
          <input name="name" required defaultValue={ca ? freeName(`${slug(ca.name)}-share`, names) : undefined} />
        </FieldShell>
        <FieldShell label="Resource ARNs" rule={rules.resources} member="resourceArns">
          <textarea name="resources" rows={ca ? 1 : 3} defaultValue={ca?.arn} placeholder="arn:aws:acm-pca:…:certificate-authority/…" />
        </FieldShell>
        <FieldShell label="Principals" rule={rules.principals} member="principals">
          <textarea name="principals" rows={2} defaultValue={org} placeholder="111122223333 or an OU / organization ARN" />
        </FieldShell>
        <label className="check">
          <input type="checkbox" name="external" /> Allow sharing outside the organization
        </label>
        {children && <MoreFields>{children}</MoreFields>}
      </div>
    </>
  );
}

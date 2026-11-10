"use client";

// A hosted zone starts from where it answers: the internet (public), or one
// of the account's VPCs (private). Description and delegation set wait under More.

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { CreateHostedZone } from "@mws-dashboard/ui/model/route53";
import { MoreFields, PresetGallery, type PresetItem } from "@mws-dashboard/ui/presets";
import { useState } from "react";

export function ZoneFields({ vpcs, sets }: { vpcs: { id: string; name: string; cidr?: string }[]; sets: { id: string; label: string }[] }) {
  const items: (PresetItem & { vpc: string })[] = [
    { id: "public", vpc: "", label: "Public", icon: "resource/Internet", title: "Answers on the internet" },
    ...vpcs.map((v) => ({ id: v.id, vpc: v.id, label: v.name, icon: "resource/AmazonVPCVirtualprivatecloudVPC", group: "Private to a VPC", title: v.cidr ? `${v.id} · ${v.cidr}` : v.id })),
  ];
  const [type, setType] = useState(items[0]);
  return (
    <>
      {items.length > 1 && <PresetGallery presets={items} chosen={type.id} choose={setType} label="Type" testId="zone-type" />}
      <input type="hidden" name="vpc" value={type.vpc} />
      <Field label="Domain name" rule={CreateHostedZone.Name} format="domain" unique>
        <input name="name" placeholder={type.vpc ? "internal.example" : "example.com"} autoFocus />
      </Field>
      <MoreFields>
        <Field label="Description" rule={CreateHostedZone.HostedZoneConfig.fields?.Comment} member="HostedZoneConfig.Comment">
          <input name="comment" />
        </Field>
        {!type.vpc && sets.length > 0 && (
          <Field label="Reusable delegation set" rule={CreateHostedZone.DelegationSetId} member="DelegationSetId">
            <select name="delegationSet" defaultValue="">
              <option value="">New name servers</option>
              {sets.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.label}
                </option>
              ))}
            </select>
          </Field>
        )}
      </MoreFields>
    </>
  );
}

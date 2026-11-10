"use client";

// The launch form's fields, shared by "Launch instance", "Create launch
// template" and "New version". Client-side because the choices depend on
// each other: the security groups follow the subnet's VPC, a public IP
// choice needs a subnet, the root volume starts at the image's size, and a
// launch template makes the image optional.

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { MoreFields, PresetGallery, type PresetItem } from "@mws-dashboard/ui/presets";
import type { Rule } from "@mws-dashboard/ui/validation";
import { Section, Sections } from "@mws-dashboard/ui/sections";
import { useMemo, useState, type ReactNode } from "react";

import { OS_FAMILIES, SIZES, familyImage, osLogo } from "./os";
import { COUNT, IMAGE, INSTANCE_TYPE, ROOT_SIZE, TAG_VALUE, VOLUME_TYPE, VOLUME_TYPES } from "./rules";

export interface LaunchChoices {
  images: {
    id: string;
    name?: string;
    arch?: string;
    root?: string;
    size?: number;
    mine?: boolean;
    created?: string;
  }[];
  types: string[];
  keys: string[];
  subnets: {
    id: string;
    label: string;
    vpc: string;
    vpcLabel: string;
    zone: string;
    publicIp: boolean;
  }[];
  groups: { id: string; name: string; vpc: string }[];
  profiles: { name: string; arn: string }[];
  templates: { id: string; name: string; latest: number; default: number }[];
  defaultVpc?: string;
}

type ImageTile = PresetItem & { image: string };

/** OS tiles (the newest general-purpose image of each family), then the account's own AMIs. */
function imageTiles(images: LaunchChoices["images"]): ImageTile[] {
  const families = OS_FAMILIES.flatMap((f) => {
    const i = familyImage(
      f,
      images.filter((x) => !x.mine),
    );
    return i ? [{ id: f.id, label: f.label, icon: f.icon, title: i.name, image: i.id }] : [];
  });
  const mine = images
    .filter((i) => i.mine)
    .sort((a, b) => (b.created ?? "").localeCompare(a.created ?? ""))
    .slice(0, 6)
    .map((i) => ({
      id: i.id,
      label: i.name ?? i.id,
      icon: osLogo(i.name) ?? "resource/AmazonEC2AMI",
      title: `${i.name ?? ""} ${i.id}`.trim(),
      image: i.id,
      group: "My AMIs",
    }));
  return [
    ...families.map((f) => ({
      ...f,
      group: mine.length ? "Quick start" : undefined,
    })),
    ...mine,
  ];
}

/** Size tiles lead with the memory, the number people choose by. */
const SIZE_TILES: PresetItem[] = SIZES.map((s) => ({
  id: s.type,
  label: s.type,
  title: `${s.label} · ${s.vcpu} vCPU · ${s.mem}`,
  icon: <b className="text-sm font-semibold">{s.mem}</b>,
}));

export function LaunchFields({
  choices,
  mode,
  template,
  image: initialImage,
  details,
}: {
  choices: LaunchChoices;
  mode: "launch" | "template" | "version";
  template?: string;
  image?: string;
  /** Fields for the last step (a template's name and description). */
  details?: ReactNode;
}) {
  const { images, subnets, groups, profiles, templates } = choices;
  const tiles = useMemo(() => imageTiles(images), [images]);
  const [templateId, setTemplateId] = useState(template ?? "");
  const [image, setImage] = useState(initialImage ?? (mode === "launch" && !template ? (tiles[0]?.image ?? images[0]?.id ?? "") : ""));
  const [type, setType] = useState(mode === "launch" && !template ? "t3.micro" : "");
  const [subnet, setSubnet] = useState("");
  const chosenSubnet = subnets.find((s) => s.id === subnet);
  const vpc = chosenSubnet?.vpc ?? choices.defaultVpc;
  const vpcGroups = groups.filter((g) => !vpc || g.vpc === vpc);
  const chosenImage = images.find((i) => i.id === image);
  const optionalImage = mode !== "launch" || !!templateId;
  const chosenTemplate = templates.find((t) => t.id === templateId);

  // An image's name stands for its ID: typing one offers the ID.
  const imageRule = useMemo<Rule>(
    () => ({
      ...IMAGE,
      required: !optionalImage,
      known: images.map((i) => i.id),
      aliases: Object.fromEntries(images.filter((i) => i.name).map((i) => [i.name!, i.id])),
    }),
    [images, optionalImage],
  );
  const rootRule = useMemo<Rule>(
    () => ({
      ...ROOT_SIZE,
      ...(chosenImage?.size ? { min: chosenImage.size } : {}),
    }),
    [chosenImage],
  );
  const vpcs = [...new Map(subnets.map((s) => [s.vpc, s.vpcLabel])).entries()];

  const chosenTile = tiles.find((t) => t.image === image);

  return (
    <Sections testId="launch">
      <Section id="image" label="Image" summary={chosenTile?.label}>
      {tiles.length > 0 && <PresetGallery presets={tiles} chosen={chosenTile?.id} choose={(t) => setImage(t.image)} label="Image" testId="launch-os" />}
      {mode === "launch" && templates.length > 0 && !template && (
        <Field label="Launch template" member="LaunchTemplate">
          <select name="launchTemplate" value={templateId} onChange={(e) => setTemplateId(e.target.value)}>
            <option value="">None</option>
            {templates.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </select>
        </Field>
      )}
      {template && <input type="hidden" name="launchTemplate" value={template} />}
      {mode === "launch" && chosenTemplate && (
        <Field label="Template version">
          <select name="templateVersion" defaultValue="$Default">
            <option value="$Default">Default ({chosenTemplate.default})</option>
            <option value="$Latest">Latest ({chosenTemplate.latest})</option>
            {Array.from({ length: chosenTemplate.latest }, (_, n) => n + 1)
              .reverse()
              .map((v) => (
                <option key={v} value={String(v)}>
                  {v}
                </option>
              ))}
          </select>
        </Field>
      )}
      <Field
        label="Image"
        rule={imageRule}
        member="ImageId"
        hint={optionalImage && !image ? "Blank: the template's" : chosenImage?.name && chosenImage.name !== chosenTile?.label ? chosenImage.name : undefined}
      >
        <input name="image" list="launch-images" value={image} onChange={(e) => setImage(e.target.value)} required={!optionalImage} />
      </Field>
      <datalist id="launch-images">
        {images.map((i) => (
          <option key={i.id} value={i.id}>
            {[i.name, i.arch].filter(Boolean).join(" · ")}
          </option>
        ))}
      </datalist>
      </Section>
      <Section id="size" label="Size" summary={type || undefined}>
      <PresetGallery presets={SIZE_TILES} chosen={type} choose={(t) => setType(type === t.id && optionalImage ? "" : t.id)} label="Size" testId="launch-size" />
      <Field label="Instance type" rule={INSTANCE_TYPE} member="InstanceType" hint={optionalImage && !type ? "Blank: the template's" : undefined}>
        <input name="type" value={type} onChange={(e) => setType(e.target.value)} list="launch-types" />
      </Field>
      <datalist id="launch-types">
        {choices.types.map((t) => (
          <option key={t} value={t} />
        ))}
      </datalist>
      {choices.keys.length > 0 && (
        <Field label="Key pair">
          <select name="keyName" defaultValue="">
            <option value="">None</option>
            {choices.keys.map((k) => (
              <option key={k}>{k}</option>
            ))}
          </select>
        </Field>
      )}
      </Section>
      <Section id="network" label="Network and storage">
        <Field label="Subnet" member="SubnetId">
          <select name="subnet" value={subnet} onChange={(e) => setSubnet(e.target.value)}>
            <option value="">Default subnet</option>
            {vpcs.map(([id, label]) => (
              <optgroup key={id} label={label}>
                {subnets
                  .filter((s) => s.vpc === id)
                  .map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.label} · {s.zone}
                    </option>
                  ))}
              </optgroup>
            ))}
          </select>
        </Field>
        {subnet && (
          <Field label="Public IP" member="AssociatePublicIpAddress">
            <select name="publicIp" defaultValue="">
              <option value="">Subnet setting ({chosenSubnet?.publicIp ? "on" : "off"})</option>
              <option value="enable">Assign</option>
              <option value="disable">Don&apos;t assign</option>
            </select>
          </Field>
        )}
        {vpcGroups.length > 0 && (
          <fieldset className="checks" data-testid="launch-groups">
            <legend>Security groups</legend>
            {vpcGroups.map((g) => (
              <label key={g.id} className="check">
                <input type="checkbox" name="securityGroups" value={g.id} /> {g.name}
              </label>
            ))}
          </fieldset>
        )}
        <Field label="IAM instance profile" member="IamInstanceProfile">
          <select name="iamProfile" defaultValue="">
            <option value="">None</option>
            {profiles.map((p) => (
              <option key={p.arn} value={p.name}>
                {p.name}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Root volume (GiB)" rule={rootRule} member="VolumeSize" hint={chosenImage?.size ? `Image: ${chosenImage.size} GiB` : undefined}>
          <input name="rootSize" type="number" min={chosenImage?.size ?? 1} placeholder={chosenImage?.size ? String(chosenImage.size) : undefined} />
        </Field>
        <Field label="Root volume type" rule={VOLUME_TYPE} member="VolumeType">
          <select name="rootType" defaultValue="">
            <option value="">Image default</option>
            {VOLUME_TYPES.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </Field>
        {mode !== "launch" && <input type="hidden" name="rootDevice" value={chosenImage?.root ?? "/dev/xvda"} />}
      </Section>
      <Section id="details" label="Details">
        {mode === "launch" && (
          <div className="form-row">
            <Field label="Name" rule={TAG_VALUE}>
              <input name="name" />
            </Field>
            <Field label="Count" rule={COUNT} member="MaxCount">
              <input name="count" type="number" min={1} max={20} defaultValue={1} />
            </Field>
          </div>
        )}
        {details}
        <MoreFields label="Advanced">
        <label className="check">
          <input type="checkbox" name="protect" /> Termination protection
        </label>
        <label className="check">
          <input type="checkbox" name="monitoring" /> Detailed monitoring
        </label>
        {mode === "launch" && (
          <label className="check">
            <input type="checkbox" name="spot" /> Spot Instance
          </label>
        )}
        {mode !== "launch" && (
          <Field label="Metadata version" member="HttpTokens">
            <select name="tokens" defaultValue="">
              <option value="">Default</option>
              <option value="required">IMDSv2 only</option>
              <option value="optional">IMDSv1 and v2</option>
            </select>
          </Field>
        )}
        <textarea name="userData" rows={4} aria-label="User data" placeholder="#!/bin/bash" className="code-editor" />
        </MoreFields>
      </Section>
    </Sections>
  );
}

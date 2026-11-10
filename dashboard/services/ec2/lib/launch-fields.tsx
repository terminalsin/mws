"use client";

// The launch form's fields, shared by "Launch instance", "Create launch
// template" and "New version". Client-side because the choices depend on
// each other: the security groups follow the subnet's VPC, a public IP
// choice needs a subnet, the root volume starts at the image's size, and a
// launch template makes the image optional.

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import type { Rule } from "@mws-dashboard/ui/validation";
import { useMemo, useState } from "react";

import { COUNT, IMAGE, INSTANCE_TYPE, ROOT_SIZE, TAG_VALUE, VOLUME_TYPE, VOLUME_TYPES } from "./rules";

export interface LaunchChoices {
  images: { id: string; name?: string; arch?: string; root?: string; size?: number }[];
  types: string[];
  keys: string[];
  subnets: { id: string; label: string; vpc: string; vpcLabel: string; zone: string; publicIp: boolean }[];
  groups: { id: string; name: string; vpc: string }[];
  profiles: { name: string; arn: string }[];
  templates: { id: string; name: string; latest: number; default: number }[];
  defaultVpc?: string;
}

export function LaunchFields({ choices, mode, template, image: initialImage }: { choices: LaunchChoices; mode: "launch" | "template" | "version"; template?: string; image?: string }) {
  const { images, subnets, groups, profiles, templates } = choices;
  const [templateId, setTemplateId] = useState(template ?? "");
  const [image, setImage] = useState(initialImage ?? (mode === "launch" && !template ? (images[0]?.id ?? "") : ""));
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
  const rootRule = useMemo<Rule>(() => ({ ...ROOT_SIZE, ...(chosenImage?.size ? { min: chosenImage.size } : {}) }), [chosenImage]);
  const vpcs = [...new Map(subnets.map((s) => [s.vpc, s.vpcLabel])).entries()];

  return (
    <>
      {mode === "launch" && (
        <Field label="Name" rule={TAG_VALUE}>
          <input name="name" autoFocus />
        </Field>
      )}
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
      <Field label="Image" rule={imageRule} member="ImageId" hint={optionalImage ? "Blank: the template's" : undefined}>
        <input name="image" list="launch-images" value={image} onChange={(e) => setImage(e.target.value)} required={!optionalImage} />
      </Field>
      <datalist id="launch-images">
        {images.map((i) => (
          <option key={i.id} value={i.id}>
            {[i.name, i.arch].filter(Boolean).join(" · ")}
          </option>
        ))}
      </datalist>
      <Field label="Instance type" rule={INSTANCE_TYPE} member="InstanceType">
        <input name="type" defaultValue={mode === "launch" && !templateId ? "t3.micro" : ""} list="launch-types" />
      </Field>
      <datalist id="launch-types">
        {choices.types.map((t) => (
          <option key={t} value={t} />
        ))}
      </datalist>
      <Field label="Key pair">
        <select name="keyName" defaultValue="">
          <option value="">None</option>
          {choices.keys.map((k) => (
            <option key={k}>{k}</option>
          ))}
        </select>
      </Field>
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
      {mode === "launch" && (
        <Field label="Count" rule={COUNT} member="MaxCount">
          <input name="count" type="number" min={1} max={20} defaultValue={1} />
        </Field>
      )}
      <details>
        <summary>Advanced details</summary>
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
      </details>
    </>
  );
}


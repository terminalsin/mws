"use client";

// Create forms that open on logos: a recipe on its base image (one tile per
// Amazon-managed OS image, then the account's own), a component on a
// document template. Rare fields wait under More.

import type { Rule } from "@mws-dashboard/ui";
import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import { iconUrl } from "@mws-dashboard/ui/catalog";
import { useState } from "react";

import { componentIcon, imageLabel, osLogo } from "./logos";

export interface ParentImage {
  arn: string;
  name: string;
  os?: string;
  own?: boolean;
}

export interface ComponentOption {
  arn: string;
  name: string;
  own: boolean;
}

export function RecipeFields({
  parents,
  components,
  names,
  rules,
}: {
  parents: ParentImage[];
  components: ComponentOption[];
  names: string[];
  rules: Record<"name" | "version" | "parent" | "workdir" | "userData", Rule | undefined>;
}) {
  const tiles = parents
    .slice(0, 18)
    .map((p) => ({ id: p.arn, label: imageLabel(p.name), title: p.name, icon: osLogo(`${p.name} ${p.os ?? ""}`), group: parents.some((x) => x.own) ? (p.own ? "My images" : "Amazon") : undefined }));
  const [parent, setParent] = useState(parents[0]?.arn ?? "");
  return (
    <>
      {tiles.length > 0 && <PresetGallery presets={tiles} chosen={parent} choose={(t) => setParent(t.id)} label="Base image" testId="parent" />}
      <div className="form-row">
        <Field label="Name" rule={rules.name}>
          <input name="name" required autoFocus defaultValue={freeName("my-recipe", names)} />
        </Field>
        <Field label="Version" rule={rules.version} format="semver" member="semanticVersion" unique>
          <input name="version" required defaultValue="1.0.0" />
        </Field>
      </div>
      <fieldset className="checks">
        <legend>Components</legend>
        {components.map((c) => (
          <label key={c.arn} className="check">
            <input type="checkbox" name="component" value={c.arn} defaultChecked={c.name === "update-linux"} />
            <img src={iconUrl(componentIcon(c.name))} alt="" width={16} height={16} style={{ width: 16, height: 16 }} /> {c.name}
          </label>
        ))}
      </fieldset>
      <MoreFields>
        <Field label="Base image" rule={rules.parent} member="parentImage" hint="An Image Builder image, an AMI ID or ssm:/parameter" known={parents.map((p) => p.arn)}>
          <input name="parent" required list="imagebuilder-parents" value={parent} onChange={(e) => setParent(e.target.value)} spellCheck={false} />
        </Field>
        <datalist id="imagebuilder-parents">
          {parents.map((p) => (
            <option key={p.arn} value={p.arn}>
              {p.name}
            </option>
          ))}
        </datalist>
        <Field label="Working directory" rule={rules.workdir}>
          <input name="workdir" placeholder="/tmp" spellCheck={false} />
        </Field>
        <Field label="User data" rule={rules.userData}>
          <textarea name="userData" rows={3} spellCheck={false} placeholder="#!/bin/bash" />
        </Field>
      </MoreFields>
    </>
  );
}

const doc = (name: string, build: string[], validate: string[]) =>
  `name: ${name}
schemaVersion: 1.0
phases:
  - name: build
    steps:
      - name: Install
        action: ExecuteBash
        inputs:
          commands:
${build.map((c) => `            - ${c}`).join("\n")}
  - name: validate
    steps:
      - name: Check
        action: ExecuteBash
        inputs:
          commands:
${validate.map((c) => `            - ${c}`).join("\n")}
`;

const TEMPLATES = [
  { id: "nginx", label: "nginx", icon: "brand/nginx", data: doc("install-nginx", ["sudo dnf install -y nginx", "sudo systemctl enable nginx"], ["nginx -v"]) },
  { id: "docker", label: "Docker", icon: "brand/docker", data: doc("install-docker", ["sudo dnf install -y docker", "sudo systemctl enable docker"], ["docker --version"]) },
  { id: "nodejs", label: "Node.js", icon: "brand/nodedotjs", data: doc("install-nodejs", ["sudo dnf install -y nodejs"], ["node --version"]) },
  { id: "python", label: "Python", icon: "brand/python", data: doc("install-python", ["sudo dnf install -y python3 python3-pip"], ["python3 --version"]) },
  { id: "git", label: "Git", icon: "brand/git", data: doc("install-git", ["sudo dnf install -y git"], ["git --version"]) },
  { id: "script", label: "Script", icon: "brand/gnubash", data: doc("run-script", ["echo 'Hello from Image Builder'"], ["true"]) },
];

export function ComponentFields({ names, rules }: { names: string[]; rules: Record<"name" | "version" | "data", Rule | undefined> }) {
  const [t, setT] = useState(TEMPLATES[0]);
  return (
    <>
      <PresetGallery presets={TEMPLATES} chosen={t.id} choose={setT} label="Template" testId="component-template" />
      <div key={t.id}>
        <div className="form-row">
          <Field label="Name" rule={rules.name}>
            <input name="name" required autoFocus defaultValue={freeName(t.data.slice(6, t.data.indexOf("\n")), names)} />
          </Field>
          <Field label="Version" rule={rules.version} format="semver" member="semanticVersion" unique>
            <input name="version" required defaultValue="1.0.0" />
          </Field>
        </div>
        <Field label="Document" rule={rules.data}>
          <textarea name="data" rows={16} className="code-editor" spellCheck={false} defaultValue={t.data} />
        </Field>
      </div>
    </>
  );
}

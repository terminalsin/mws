"use client";

// The create-CA form opens on what the CA is for (a root, an issuing CA
// under one, a short-lived or post-quantum root): the tile sets the type,
// mode and key, so a common name is all that is left. The subject's other
// parts, key storage, revocation and tags wait under More.

import type { Rule } from "@mws-dashboard/ui";
import { FieldShell } from "@mws-dashboard/ui/fields";
import { CreateCertificateAuthority } from "@mws-dashboard/ui/model/acm-pca";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import { Atom, BadgeCheck, File, FileCode, GitBranch, RadioTower, Server, Timer, UserRound } from "lucide-react";
import { useState, type ReactNode } from "react";

import { CA_PRESETS, KEY_ALGORITHMS, TEMPLATES, TEMPLATE_ICONS, keyLabel, type CaPreset } from "./pca";

const LUCIDE: Record<string, ReactNode> = {
  "lucide:git-branch": <GitBranch size={26} aria-hidden />,
  "lucide:timer": <Timer size={26} aria-hidden />,
  "lucide:atom": <Atom size={26} aria-hidden />,
  "lucide:badge-check": <BadgeCheck size={24} aria-hidden />,
  "lucide:user-round": <UserRound size={24} aria-hidden />,
  "lucide:server": <Server size={24} aria-hidden />,
  "lucide:file-code": <FileCode size={24} aria-hidden />,
  "lucide:radio-tower": <RadioTower size={24} aria-hidden />,
  "lucide:file": <File size={24} aria-hidden />,
};

const SUBJECT = CreateCertificateAuthority.CertificateAuthorityConfiguration.fields!.Subject.fields!;
// The model allows any two letters; a real ISO code is what clients expect,
// so names ("Germany"), alpha-3 ("DEU") and withdrawn codes ("UK") repair.
const COUNTRY: Rule = { format: "country" };

export function CaFields({ names, hasRoot, children }: { names: string[]; hasRoot: boolean; children?: ReactNode }) {
  const [p, setP] = useState<CaPreset>(CA_PRESETS[0]);
  return (
    <>
      <PresetGallery
        label="CA"
        presets={CA_PRESETS.map((x) => ({ ...x, icon: LUCIDE[x.icon] ?? x.icon, found: x.id === "subordinate" && hasRoot }))}
        chosen={p.id}
        choose={(x) => setP(CA_PRESETS.find((y) => y.id === x.id)!)}
        testId="ca-preset"
      />
      <div key={p.id} className="preset-fields">
        <input type="hidden" name="type" value={p.type} />
        <input type="hidden" name="usage" value={p.usage} />
        <FieldShell label="Common name" rule={SUBJECT.CommonName} member="Subject.CommonName">
          <input name="cn" required defaultValue={freeName(p.cn, names)} placeholder="Example Root CA" />
        </FieldShell>
        <FieldShell label="Key algorithm" member="KeyAlgorithm">
          <select name="key" defaultValue={p.key}>
            {KEY_ALGORITHMS.map((k) => (
              <option key={k} value={k}>
                {keyLabel(k)}
              </option>
            ))}
          </select>
        </FieldShell>
        <MoreFields>
          <div className="form-row">
            <FieldShell label="Organization" rule={SUBJECT.Organization} member="Subject.Organization">
              <input name="org" />
            </FieldShell>
            <FieldShell label="Organizational unit" rule={SUBJECT.OrganizationalUnit} member="Subject.OrganizationalUnit">
              <input name="ou" />
            </FieldShell>
          </div>
          <div className="form-row">
            <FieldShell label="Country" rule={COUNTRY} member="Subject.Country">
              <input name="country" placeholder="US" />
            </FieldShell>
            <FieldShell label="State" rule={SUBJECT.State} member="Subject.State">
              <input name="state" />
            </FieldShell>
            <FieldShell label="Locality" rule={SUBJECT.Locality} member="Subject.Locality">
              <input name="locality" />
            </FieldShell>
          </div>
          <FieldShell label="Key storage" member="KeyStorageSecurityStandard">
            <select name="storage" defaultValue="">
              <option value="">FIPS 140-2 level 3 or higher</option>
              <option value="FIPS_140_2_LEVEL_2_OR_HIGHER">FIPS 140-2 level 2 or higher</option>
              <option value="CCPC_LEVEL_1_OR_HIGHER">CCPC level 1 or higher</option>
            </select>
          </FieldShell>
          {children}
        </MoreFields>
      </div>
    </>
  );
}

/** The issue form's template, as tiles (a hidden field carries the choice). */
export function TemplatePicker() {
  const [t, setT] = useState<string>(TEMPLATES[0].id);
  return (
    <>
      <PresetGallery
        label="Template"
        size={24}
        presets={TEMPLATES.map((x) => ({ id: x.id, label: x.label, icon: LUCIDE[TEMPLATE_ICONS[x.id]] ?? "", title: x.id }))}
        chosen={t}
        choose={(x) => setT(x.id)}
        testId="template"
      />
      <input type="hidden" name="template" value={t} />
    </>
  );
}

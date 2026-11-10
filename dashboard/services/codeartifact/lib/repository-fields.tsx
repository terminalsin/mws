"use client";

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { CreateRepository } from "@mws-dashboard/ui/model/codeartifact";
import { freeName, MoreFields, PresetGallery } from "@mws-dashboard/ui/presets";
import { Lock } from "lucide-react";
import { useState, type ReactNode } from "react";

import { EXTERNAL, EXTERNAL_INFO } from "./external";

const NAME = { ...CreateRepository.repository, generate: "name" as const };
const DOMAIN = { ...CreateRepository.domain, generate: "name" as const };

/** The ecosystems a new repository can proxy, plus one with no upstream. */
const PRESETS = [
  ...EXTERNAL.filter(([v]) => v !== "public:maven-commonsware").map(([v, label]) => ({ id: v, label, icon: EXTERNAL_INFO[v].icon as string | ReactNode, name: EXTERNAL_INFO[v].name })),
  { id: "private", label: "Private", icon: <Lock size={24} aria-hidden />, name: "packages" },
];

/** The create-repository fields. The sheet opens on the public repository
 * to proxy (npm, PyPI, ...), which names the repository; names are unique
 * within a domain and upstreams must live in the same domain, so both
 * follow the domain picked. With no domain yet, one is made on the way. */
export function RepositoryFields({ domains, repos }: { domains: string[]; repos: { domain: string; name: string }[] }) {
  const [domain, setDomain] = useState(domains[0] ?? "");
  const [preset, setPreset] = useState(PRESETS[0]);
  const inDomain = repos.filter((r) => r.domain === domain).map((r) => r.name);
  const added = new Set(inDomain);
  return (
    <>
      <PresetGallery
        label="Public upstream"
        presets={PRESETS.map((p) => ({ ...p, added: added.has(p.name) }))}
        chosen={preset.id}
        choose={(p) => setPreset(PRESETS.find((x) => x.id === p.id)!)}
      />
      {!domains.length && <input type="hidden" name="newDomain" value="on" />}
      <input type="hidden" name="external" value={preset.id === "private" ? "" : preset.id} />
      <div className="form-row">
        <Field key={preset.id} label="Repository name" rule={NAME} taken={inDomain} unique>
          <input name="name" required defaultValue={freeName(preset.name, inDomain)} />
        </Field>
        {domains.length ? (
          <Field label="Domain" rule={CreateRepository.domain}>
            <select name="domain" value={domain} onChange={(e) => setDomain(e.target.value)}>
              {domains.map((d) => (
                <option key={d} value={d}>
                  {d}
                </option>
              ))}
            </select>
          </Field>
        ) : (
          <Field label="Domain" rule={DOMAIN} hint="Created with the repository">
            <input name="domain" required defaultValue="my-domain" />
          </Field>
        )}
      </div>
      <MoreFields>
        {inDomain.length > 0 && (
          <Field key={domain} label="Upstream repository" member="repositoryName">
            <select name="upstream" defaultValue="">
              <option value="">None</option>
              {inDomain.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </Field>
        )}
        <Field label="Description" rule={CreateRepository.description}>
          <input name="description" maxLength={1000} />
        </Field>
      </MoreFields>
    </>
  );
}

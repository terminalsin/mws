"use client";

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { CreateRepository } from "@mws-dashboard/ui/model/codeartifact";
import { useState } from "react";

import { EXTERNAL } from "./external";

const NAME = { ...CreateRepository.repository, generate: "name" as const };

/** The create-repository fields. Repository names are unique within a
 * domain and upstreams must live in the same domain, so both follow the
 * domain picked. */
export function RepositoryFields({ domains, repos }: { domains: string[]; repos: { domain: string; name: string }[] }) {
  const [domain, setDomain] = useState(domains[0] ?? "");
  const inDomain = repos.filter((r) => r.domain === domain).map((r) => r.name);
  return (
    <>
      <Field label="Repository name" rule={NAME} taken={inDomain} unique>
        <input name="name" required autoFocus />
      </Field>
      <Field label="Domain" rule={CreateRepository.domain}>
        <select name="domain" value={domain} onChange={(e) => setDomain(e.target.value)}>
          {domains.map((d) => (
            <option key={d} value={d}>
              {d}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Public upstream" member="externalConnection">
        <select name="external" defaultValue="">
          <option value="">None</option>
          {EXTERNAL.map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </select>
      </Field>
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
    </>
  );
}

"use client";

import { ActionForm, Field } from "@mws-dashboard/ui";
import { CreatePullThroughCacheRule } from "@mws-dashboard/ui/model/ecr";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import { Cloud } from "lucide-react";
import { useState } from "react";

import { UPSTREAM_PRESETS, type UpstreamPreset } from "../../lib/presets";
import { createPullThrough } from "./actions";

/** The pull through cache rule form: it opens on the upstream registries'
 * logos. Public ones need one click; those that need a login ask for the
 * secret right away. */
export function PullThroughForm({ prefixes, upstreams }: { prefixes: string[]; upstreams: string[] }) {
  const [preset, setPreset] = useState<UpstreamPreset>(UPSTREAM_PRESETS[0]);
  return (
    <ActionForm action={createPullThrough} submit="Create" testId="create-pull-through">
      <PresetGallery
        presets={UPSTREAM_PRESETS.map((p) => ({ ...p, icon: p.icon || <Cloud size={26} strokeWidth={1.5} aria-hidden />, title: p.url, added: upstreams.includes(p.id) }))}
        chosen={preset.id}
        choose={(p) => setPreset(UPSTREAM_PRESETS.find((u) => u.id === p.id)!)}
        label="Upstream"
      />
      <input type="hidden" name="upstream" value={preset.id} />
      <div key={preset.id} className="preset-fields">
        <Field label="Repository prefix" rule={CreatePullThroughCacheRule.ecrRepositoryPrefix} member="ecrRepositoryPrefix" taken={prefixes} unique>
          <input name="prefix" required defaultValue={freeName(preset.prefix, prefixes)} />
        </Field>
        {preset.own && (
          <Field label="Upstream registry URL" member="upstreamRegistryUrl">
            <input name="url" required placeholder={preset.url} />
          </Field>
        )}
        {preset.login && (
          <Field label="Credentials (Secrets Manager ARN)" rule={{ ...CreatePullThroughCacheRule.credentialArn, required: true }} member="credentialArn" hint="A secret named ecr-pullthroughcache/… with username and accessToken">
            <input name="credential" required />
          </Field>
        )}
        {!preset.own && (
          <MoreFields>
            <Field label="Upstream registry URL" member="upstreamRegistryUrl">
              <input name="url" required defaultValue={preset.url} />
            </Field>
            {!preset.login && (
              <Field label="Credentials (Secrets Manager ARN)" rule={{ ...CreatePullThroughCacheRule.credentialArn, required: false }} member="credentialArn">
                <input name="credential" />
              </Field>
            )}
          </MoreFields>
        )}
      </div>
    </ActionForm>
  );
}

"use client";

// The create-app fields. The sheet opens on where the code comes from:
// an upload needs nothing but a name; a Git host adds its repository and
// token, and a framework tile that fills in the platform and build spec.

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { freeName, MoreFields, PresetGallery } from "@mws-dashboard/ui/presets";
import { ExternalLink, Upload } from "lucide-react";
import { useState } from "react";

import { buildSpec, FRAMEWORKS, SOURCES, type Framework, type Source } from "./presets";
import { APP_NAME, BRANCH, CreateApp } from "./rules";

export function AppFields({ names, roles }: { names: string[]; roles: { value: string; label: string }[] }) {
  const [source, setSource] = useState<Source>(SOURCES[0]);
  const [framework, setFramework] = useState<Framework>(FRAMEWORKS[0]);
  const git = source.id !== "manual";
  const fw = git ? framework : FRAMEWORKS[0];
  const spec = git ? buildSpec(fw) : undefined;
  return (
    <>
      <PresetGallery
        label="Source"
        testId="source"
        presets={SOURCES.map((s) => ({ ...s, icon: s.icon || <Upload size={26} aria-hidden />, title: s.id === "manual" ? "Deploy a zip or HTML without Git" : s.label }))}
        chosen={source.id}
        choose={(p) => setSource(SOURCES.find((s) => s.id === p.id)!)}
      />
      {git && <PresetGallery label="Framework" testId="framework" presets={FRAMEWORKS} chosen={framework.id} choose={setFramework} />}
      {/* Fields remount per choice, so each starts from its defaults. */}
      <div key={`${source.id}/${fw.id}`}>
        <div className="form-row">
          <Field label="App name" rule={APP_NAME}>
            <input name="name" required defaultValue={freeName(git && fw.id !== "static" ? `${fw.id}-site` : "my-site", names)} />
          </Field>
          <Field label="Branch" rule={{ ...BRANCH, required: false }} member="branchName">
            <input name="branch" defaultValue="main" />
          </Field>
        </div>
        {git && (
          <>
            <Field label="Repository" rule={CreateApp.repository} format="url">
              <input name="repository" placeholder={source.repo} />
            </Field>
            <Field
              label="Access token"
              rule={CreateApp.accessToken}
              member="accessToken"
              hint={
                source.tokenUrl ? (
                  <a href={source.tokenUrl} target="_blank" rel="noreferrer" className="inline-link">
                    {new URL(source.tokenUrl).hostname} <ExternalLink size={11} aria-hidden />
                  </a>
                ) : undefined
              }
            >
              <input name="token" type="password" autoComplete="off" />
            </Field>
          </>
        )}
        <input type="hidden" name="framework" value={fw.framework} />
        <MoreFields>
          <div className="form-row">
            <Field label="Platform" rule={CreateApp.platform}>
              <select name="platform" defaultValue={fw.platform}>
                <option value="WEB">Static (WEB)</option>
                <option value="WEB_COMPUTE">SSR (WEB_COMPUTE)</option>
                <option value="WEB_DYNAMIC">WEB_DYNAMIC</option>
              </select>
            </Field>
            <Field label="Service role">
              <select name="role" defaultValue="">
                <option value="">None</option>
                {roles.map((r) => (
                  <option key={r.value} value={r.value}>
                    {r.label}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <Field label="Environment variables" format="env">
            <textarea name="env" rows={2} placeholder="API_URL=https://api.example.com" />
          </Field>
          {git && (
            <Field label="Build specification" format="yaml" rule={CreateApp.buildSpec}>
              <textarea name="buildSpec" rows={6} className="code-editor" spellCheck={false} defaultValue={spec} placeholder="The repository's amplify.yml" />
            </Field>
          )}
        </MoreFields>
      </div>
    </>
  );
}

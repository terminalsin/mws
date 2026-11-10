"use client";

// "Create function" opens on the languages: picking one fills its newest
// runtime and, where the console has starter code, needs nothing else. A
// language without a starter asks for its .zip; a container image asks for
// its URI. The rest waits under More.

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { CreateFunction } from "@mws-dashboard/ui/model/lambda";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import { useState } from "react";

import { FUNCTION_NAME, HANDLER } from "./rules";
import { RUNTIME_PRESETS } from "./runtimes";

export function CreateFunctionFields({ names }: { names: string[] }) {
  const [preset, setPreset] = useState(RUNTIME_PRESETS[0]);
  const image = preset.runtimes.length === 0;
  const zip = !preset.starter && !image;
  return (
    <>
      <PresetGallery presets={RUNTIME_PRESETS} chosen={preset.id} choose={setPreset} label="Runtime" testId="runtime" />
      <Field label="Name" rule={FUNCTION_NAME} taken={names} unique>
        <input name="name" required autoFocus defaultValue={freeName("my-function", names)} />
      </Field>
      <div key={preset.id}>
        {image ? (
          <Field label="Container image URI">
            <input name="image" required placeholder="123456789012.dkr.ecr.us-east-1.amazonaws.com/app:latest" spellCheck={false} />
          </Field>
        ) : (
          <>
            {preset.runtimes.length > 1 && (
              <Field label="Runtime" rule={CreateFunction.Runtime}>
                <select name="runtime" defaultValue={preset.runtimes[0]}>
                  {preset.runtimes.map((r) => (
                    <option key={r}>{r}</option>
                  ))}
                </select>
              </Field>
            )}
            {preset.runtimes.length === 1 && <input type="hidden" name="runtime" value={preset.runtimes[0]} />}
            {zip && (
              <div className="form-row">
                <Field label=".zip file">
                  <input type="file" name="zip" accept=".zip,application/zip" required />
                </Field>
                <Field label="Handler" rule={HANDLER}>
                  <input name="handler" defaultValue={preset.handler} spellCheck={false} />
                </Field>
              </div>
            )}
          </>
        )}
        <MoreFields>
          <Field label="Architecture">
            <select name="arch" defaultValue="arm64">
              <option>arm64</option>
              <option>x86_64</option>
            </select>
          </Field>
          {preset.starter && (
            <>
              <Field label=".zip file" hint="Replaces the starter code">
                <input type="file" name="zip" accept=".zip,application/zip" />
              </Field>
              <Field label="Handler" rule={HANDLER}>
                <input name="handler" placeholder={preset.id === "nodejs" ? "index.handler" : "lambda_function.lambda_handler"} spellCheck={false} />
              </Field>
            </>
          )}
        </MoreFields>
      </div>
    </>
  );
}

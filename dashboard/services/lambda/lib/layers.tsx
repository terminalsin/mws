import { ActionForm, Field, Sheet } from "@mws-dashboard/ui";
import { MoreFields } from "@mws-dashboard/ui/presets";

import { publishLayer } from "../routes/lambda/actions";
import { RUNTIMES } from "./clients";
import { LAYER_DESCRIPTION, LAYER_NAME } from "./rules";

export function PublishLayer({ name, names = [] }: { name?: string; names?: string[] }) {
  return (
    <Sheet title={name ? `New version of ${name}` : "New layer"} label={name ? "Create version" : "Create layer"} testId="publish-layer">
      <ActionForm action={publishLayer} submit="Create" testId="publish-layer">
        {name ? (
          <input type="hidden" name="name" value={name} />
        ) : (
          <Field label="Name" rule={LAYER_NAME} known={names}>
            <input name="name" required autoFocus spellCheck={false} />
          </Field>
        )}
        <Field label=".zip file">
          <input type="file" name="zip" accept=".zip,application/zip" required />
        </Field>
        <Field label="Compatible runtimes">
          <select name="runtimes" multiple size={4}>
            {RUNTIMES.map((r) => (
              <option key={r}>{r}</option>
            ))}
          </select>
        </Field>
        <MoreFields>
          <Field label="Description" rule={LAYER_DESCRIPTION}>
            <input name="description" />
          </Field>
          <div className="form-row">
            <label className="check">
              <input type="checkbox" name="archs" value="x86_64" /> x86_64
            </label>
            <label className="check">
              <input type="checkbox" name="archs" value="arm64" /> arm64
            </label>
          </div>
          <Field label="License">
            <input name="license" placeholder="MIT" />
          </Field>
        </MoreFields>
      </ActionForm>
    </Sheet>
  );
}

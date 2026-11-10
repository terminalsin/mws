import { ActionForm, Field, type FormAction } from "@mws-dashboard/ui";

/** Every attribute a describe call returned, editable in place: booleans
 * as on/off, the rest as text. Only changed values are sent. */
export function AttributesForm({ attributes, action, testId }: { attributes: { Key?: string; Value?: string }[]; action: FormAction; testId: string }) {
  const sorted = [...attributes].filter((a) => a.Key).sort((a, b) => a.Key!.localeCompare(b.Key!));
  return (
    <ActionForm action={action} submit="Save attributes" testId={testId}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))", columnGap: "1rem" }}>
        {sorted.map((a) => {
          const bool = a.Value === "true" || a.Value === "false";
          return (
            <div key={a.Key}>
              <input type="hidden" name={`was:${a.Key}`} value={a.Value ?? ""} />
              <Field label={a.Key!.replace(/_/g, " ")} member={`attr:${a.Key}`}>
                {bool ? (
                  <select name={`attr:${a.Key}`} defaultValue={a.Value}>
                    <option value="true">On</option>
                    <option value="false">Off</option>
                  </select>
                ) : (
                  <input name={`attr:${a.Key}`} defaultValue={a.Value ?? ""} />
                )}
              </Field>
            </div>
          );
        })}
      </div>
    </ActionForm>
  );
}

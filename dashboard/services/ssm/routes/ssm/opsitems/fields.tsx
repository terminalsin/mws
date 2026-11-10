import { Field } from "@mws-dashboard/ui";
import { CreateOpsItem } from "@mws-dashboard/ui/model/ssm";

export const SEVERITIES = ["1", "2", "3", "4"];
export const CATEGORIES = ["Availability", "Cost", "Performance", "Recovery", "Security"];

export function OpsItemFields({ d = {} }: { d?: { title?: string; description?: string; priority?: number; severity?: string; category?: string } }) {
  return (
    <>
      <Field label="Title" rule={CreateOpsItem.Title}>
        <input name="title" required defaultValue={d.title} />
      </Field>
      <Field label="Description" rule={CreateOpsItem.Description}>
        <textarea name="description" rows={4} required defaultValue={d.description} />
      </Field>
      <div className="form-row">
        <Field label="Priority" rule={CreateOpsItem.Priority}>
          <input name="priority" type="number" defaultValue={d.priority ?? 3} />
        </Field>
        <Field label="Severity" rule={{ ...CreateOpsItem.Severity, known: SEVERITIES }}>
          <select name="severity" defaultValue={d.severity ?? ""}>
            <option value="">None</option>
            {SEVERITIES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </Field>
        <Field label="Category" rule={CreateOpsItem.Category}>
          <select name="category" defaultValue={d.category ?? ""}>
            <option value="">None</option>
            {CATEGORIES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </Field>
      </div>
    </>
  );
}

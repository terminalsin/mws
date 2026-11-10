import { Field } from "@mws-dashboard/ui";
import { CreateMaintenanceWindow } from "@mws-dashboard/ui/model/ssm";

export function WindowFields({ d = {} }: { d?: { name?: string; description?: string; schedule?: string; timezone?: string; duration?: number; cutoff?: number } }) {
  return (
    <>
      <Field label="Name" rule={CreateMaintenanceWindow.Name} unique>
        <input name="name" required defaultValue={d.name} placeholder="nightly-patching" />
      </Field>
      <Field label="Description" rule={CreateMaintenanceWindow.Description}>
        <input name="description" defaultValue={d.description} />
      </Field>
      <Field label="Schedule" rule={{ ...CreateMaintenanceWindow.Schedule, hint: "cron(0 2 ? * SUN *), rate(1 day) or at(2027-01-01T02:00:00)" }}>
        <input name="schedule" required defaultValue={d.schedule ?? "cron(0 2 ? * SUN *)"} />
      </Field>
      <div className="form-row">
        <Field label="Duration (hours)" rule={CreateMaintenanceWindow.Duration}>
          <input name="duration" type="number" required defaultValue={d.duration ?? 3} />
        </Field>
        <Field label="Stop new tasks (hours before end)" rule={CreateMaintenanceWindow.Cutoff}>
          <input name="cutoff" type="number" defaultValue={d.cutoff ?? 1} />
        </Field>
        <Field label="Time zone">
          <input name="timezone" defaultValue={d.timezone} placeholder="UTC" />
        </Field>
      </div>
    </>
  );
}

"use client";

// A new window starts from when it opens: nightly, weekly or monthly. The
// choice fills the schedule, its length and a name; the rest is under More.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { CreateMaintenanceWindow } from "@mws-dashboard/ui/model/ssm";
import { freeName, MoreFields, PresetGallery, type PresetItem } from "@mws-dashboard/ui/presets";
import { CalendarClock, CalendarDays, Moon, Wrench } from "lucide-react";
import { useState } from "react";

interface When extends PresetItem {
  schedule: string;
  duration: number;
  cutoff: number;
  base: string;
}

const WHEN: When[] = [
  { id: "nightly", label: "Nightly", icon: <Moon size={24} aria-hidden />, schedule: "cron(0 2 ? * * *)", duration: 2, cutoff: 1, base: "nightly", title: "Every day at 02:00" },
  { id: "weekly", label: "Weekly", icon: <CalendarDays size={24} aria-hidden />, schedule: "cron(0 2 ? * SUN *)", duration: 3, cutoff: 1, base: "weekly-patching", title: "Sundays at 02:00" },
  { id: "monthly", label: "Monthly", icon: <CalendarClock size={24} aria-hidden />, schedule: "cron(0 3 ? * SAT#2 *)", duration: 4, cutoff: 1, base: "monthly-patching", title: "Second Saturday of the month at 03:00" },
  { id: "custom", label: "Custom", icon: <Wrench size={22} aria-hidden />, schedule: "", duration: 3, cutoff: 1, base: "" },
];

type Defaults = { name?: string; description?: string; schedule?: string; timezone?: string; duration?: number; cutoff?: number };

export function WindowFields({ d, taken = [] }: { d?: Defaults; taken?: string[] }) {
  const [when, setWhen] = useState<When>(WHEN[1]);
  const edit = !!d;
  const v = d ?? {};
  return (
    <>
      {!edit && <PresetGallery presets={WHEN} chosen={when.id} choose={setWhen} label="Opens" size={24} />}
      <div key={edit ? "edit" : when.id} className="preset-fields">
        <FieldShell label="Name" rule={CreateMaintenanceWindow.Name} unique taken={taken}>
          <input name="name" required defaultValue={edit ? v.name : when.base ? freeName(when.base, taken) : undefined} placeholder="nightly-patching" />
        </FieldShell>
        <FieldShell label="Schedule" rule={{ ...CreateMaintenanceWindow.Schedule, hint: "cron(0 2 ? * SUN *), rate(1 day) or at(2027-01-01T02:00:00)" }}>
          <input name="schedule" required defaultValue={edit ? v.schedule : when.schedule} placeholder="cron(0 2 ? * SUN *)" />
        </FieldShell>
        <div className="form-row">
          <FieldShell label="Duration (hours)" rule={CreateMaintenanceWindow.Duration}>
            <input name="duration" type="number" required defaultValue={edit ? v.duration : when.duration} />
          </FieldShell>
          <FieldShell label="Stop new tasks (hours before end)" rule={CreateMaintenanceWindow.Cutoff}>
            <input name="cutoff" type="number" defaultValue={edit ? v.cutoff : when.cutoff} />
          </FieldShell>
        </div>
        <MoreFields expanded={!!(v.description || v.timezone)}>
          <FieldShell label="Description" rule={CreateMaintenanceWindow.Description}>
            <input name="description" defaultValue={v.description} />
          </FieldShell>
          <FieldShell label="Time zone">
            <input name="timezone" defaultValue={v.timezone} placeholder="UTC" />
          </FieldShell>
          {!edit && (
            <label className="check">
              <input type="checkbox" name="unassociated" /> Allow unregistered targets
            </label>
          )}
        </MoreFields>
      </div>
    </>
  );
}

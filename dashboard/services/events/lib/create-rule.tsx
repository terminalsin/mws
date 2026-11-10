"use client";

// The create-rule form: a gallery of common rules (a schedule, your app's
// events, the AWS events people react to most), each filling a unique name
// and its pattern; the description and target role wait under More.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { freeName, MoreFields, PresetGallery } from "@mws-dashboard/ui/presets";
import { useState } from "react";

import { RULE_PRESETS } from "./rule-presets";
import { PATTERN, ROLE, RULE_DESCRIPTION, RULE_NAME, SCHEDULE, TARGET } from "./rules";

export function CreateRuleFields({ bus, taken, targets }: { bus: string; taken: string[]; targets: { arn: string; name: string }[] }) {
  // Schedules run on the default bus only.
  const presets = RULE_PRESETS.map((p) => ({ ...p, disabled: !!p.schedule && bus !== "default" }));
  const [preset, setPreset] = useState(presets[0]);
  const showPattern = preset.custom || !!preset.pattern;
  const showSchedule = bus === "default" && (preset.custom || !!preset.schedule);
  return (
    <>
      <PresetGallery presets={presets} chosen={preset.id} choose={setPreset} label="Rule type" size={26} testId="rule-preset" />
      <div key={preset.id}>
        <FieldShell label="Name" rule={RULE_NAME} taken={taken} unique>
          <input name="name" required defaultValue={preset.custom ? undefined : freeName(preset.name, taken)} spellCheck={false} />
        </FieldShell>
        {showPattern && (
          <FieldShell label="Event pattern" rule={PATTERN} member="EventPattern" format="eventPattern">
            <textarea name="pattern" rows={preset.pattern ? 4 : 3} placeholder='{"source": ["my.app"]}' defaultValue={preset.pattern ? JSON.stringify(preset.pattern, null, 2) : undefined} spellCheck={false} />
          </FieldShell>
        )}
        {showSchedule && (
          <FieldShell label={preset.custom ? "Or schedule" : "Schedule"} rule={SCHEDULE} member="ScheduleExpression" format="schedule">
            <input name="schedule" placeholder="rate(5 minutes)" defaultValue={preset.schedule} spellCheck={false} />
          </FieldShell>
        )}
        <FieldShell label="Target ARN" rule={TARGET} member="Arn" format="arn" known={targets.map((t) => t.arn)}>
          <input name="target" placeholder="arn:aws:sqs:…" list="event-targets" spellCheck={false} />
        </FieldShell>
        <datalist id="event-targets">
          {targets.map((t) => (
            <option key={t.arn} value={t.arn}>
              {t.name}
            </option>
          ))}
        </datalist>
        <label className="check">
          <input type="checkbox" name="grant" defaultChecked /> Allow the rule in the target&apos;s resource policy
        </label>
        <MoreFields>
          <FieldShell label="Description" rule={RULE_DESCRIPTION}>
            <input name="description" />
          </FieldShell>
          <FieldShell label="Target role" rule={{ ...ROLE, required: false }} member="RoleArn">
            <input name="role" placeholder="For Kinesis, Firehose, buses and API destinations" spellCheck={false} />
          </FieldShell>
        </MoreFields>
      </div>
    </>
  );
}

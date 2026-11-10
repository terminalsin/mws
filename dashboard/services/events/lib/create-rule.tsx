"use client";

// The create-rule form: a gallery of common rules (a schedule, your app's
// events, the AWS events people react to most), each filling a unique name
// and its pattern; the description and target role wait under More.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { freeName, MoreFields, PresetGallery } from "@mws-dashboard/ui/presets";
import { useState } from "react";

import { RULE_PRESETS } from "./rule-presets";
import { PATTERN, ROLE, RULE_DESCRIPTION, RULE_NAME, SCHEDULE, TARGET } from "./rules";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";
import { EventPatternEditor } from "./pattern-editor.tsx";

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
          <EventPatternEditor rule={PATTERN} rows={preset.pattern ? 4 : 3} defaultValue={preset.pattern ? JSON.stringify(preset.pattern, null, 2) : preset.custom ? undefined : ""} />
        )}
        {showSchedule && (
          <FieldShell label={preset.custom ? "Or schedule" : "Schedule"} rule={SCHEDULE} member="ScheduleExpression" format="schedule">
            <input name="schedule" placeholder="rate(5 minutes)" defaultValue={preset.schedule} spellCheck={false} />
          </FieldShell>
        )}
        <FieldShell label="Target ARN" rule={TARGET} member="Arn" format="arn" known={targets.map((t) => t.arn)}>
          <ResourcePicker kind={["lambda-function", "sqs-queue", "sns-topic", "kinesis-stream", "firehose-stream", "event-bus", "log-group"]} name="target" use="arn" />
        </FieldShell>
        <label className="check">
          <input type="checkbox" name="grant" defaultChecked /> Allow the rule in the target&apos;s resource policy
        </label>
        <MoreFields>
          <FieldShell label="Description" rule={RULE_DESCRIPTION}>
            <input name="description" />
          </FieldShell>
          <FieldShell label="Target role" rule={{ ...ROLE, required: false }} member="RoleArn">
            <ResourcePicker kind="iam-role" name="role" service="events.amazonaws.com" placeholder="For Kinesis, Firehose, buses and API destinations" />
          </FieldShell>
        </MoreFields>
      </div>
    </>
  );
}

import type { CompositeAlarm, MetricAlarm } from "@aws-sdk/client-cloudwatch";
import { ActionForm, Field, type Rule } from "@mws-dashboard/ui";
import { PutCompositeAlarm } from "@mws-dashboard/ui/model/cloudwatch";

import { ActionFields, AlarmFields } from "./alarm-fields";

export { OP, PERIODS, STATISTICS, period } from "./alarm-consts";

const TAGS: Rule = { format: "tags", maxLength: 8192 };
export interface AlarmFormProps {
  /** The alarm being edited; a new one when absent. */
  alarm?: MetricAlarm;
  namespaces: string[];
  names: string[];
  dims: string[];
  taken: string[];
  topics: string[];
  topicArn?: string;
  /** The dimensions each namespace's metrics have, for prefilling a preset. */
  dimsByNamespace?: Record<string, string[]>;
  action: (
    previous: import("@mws-dashboard/ui").ActionResult | null,
    form: FormData,
  ) => Promise<import("@mws-dashboard/ui").ActionResult>;
  testId: string;
}

export function AlarmForm({ action, testId, alarm, ...rest }: AlarmFormProps) {
  return (
    <ActionForm action={action} submit={alarm ? "Save" : "Create"} testId={testId}>
      <AlarmFields alarm={alarm} testId={testId} {...rest} />
    </ActionForm>
  );
}

export function CompositeForm({
  alarm,
  taken,
  alarms,
  topics,
  topicArn,
  action,
  testId,
}: {
  alarm?: CompositeAlarm;
  taken: string[];
  alarms: string[];
  topics: string[];
  topicArn?: string;
  action: AlarmFormProps["action"];
  testId: string;
}) {
  return (
    <ActionForm
      action={action}
      submit={alarm ? "Save" : "Create"}
      testId={testId}
    >
      {alarm ? (
        <input
          type="hidden"
          name="enabled"
          value={alarm.ActionsEnabled === false ? "off" : "on"}
        />
      ) : (
        <Field
          label="Name"
          rule={PutCompositeAlarm.AlarmName}
          taken={taken}
          generate="name"
          unique
        >
          <input name="name" autoFocus />
        </Field>
      )}
      <Field label="Description" rule={PutCompositeAlarm.AlarmDescription}>
        <input name="description" defaultValue={alarm?.AlarmDescription} />
      </Field>
      <Field
        label="Rule"
        rule={PutCompositeAlarm.AlarmRule}
        hint='ALARM("cpu-high") AND NOT OK("latency")'
      >
        <textarea
          name="rule"
          rows={3}
          className="code-editor"
          required
          defaultValue={
            alarm?.AlarmRule ?? (alarms[0] ? `ALARM("${alarms[0]}")` : "")
          }
        />
      </Field>
      <ActionFields alarm={alarm} topics={topics} topicArn={topicArn} />
      <Field
        label="Actions suppressor"
        rule={PutCompositeAlarm.ActionsSuppressor}
        known={alarms}
      >
        <input
          name="suppressor"
          list={`${testId}-alarms`}
          defaultValue={alarm?.ActionsSuppressor}
        />
      </Field>
      <datalist id={`${testId}-alarms`}>
        {alarms.map((n) => (
          <option key={n} value={n} />
        ))}
      </datalist>
      <div className="form-grid">
        <Field
          label="Wait (s)"
          rule={{
            ...PutCompositeAlarm.ActionsSuppressorWaitPeriod,
            unit: "seconds",
          }}
        >
          <input
            name="wait"
            type="number"
            defaultValue={alarm?.ActionsSuppressorWaitPeriod ?? 60}
          />
        </Field>
        <Field
          label="Extension (s)"
          rule={{
            ...PutCompositeAlarm.ActionsSuppressorExtensionPeriod,
            unit: "seconds",
          }}
        >
          <input
            name="extension"
            type="number"
            defaultValue={alarm?.ActionsSuppressorExtensionPeriod ?? 60}
          />
        </Field>
      </div>
      {!alarm && (
        <Field label="Tags" rule={TAGS}>
          <textarea name="tags" rows={1} placeholder="team=payments" />
        </Field>
      )}
    </ActionForm>
  );
}

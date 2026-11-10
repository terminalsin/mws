import { load } from "@mws-dashboard/aws";
import { ago } from "@mws-dashboard/aws";
import {
  ActionForm,
  AwsIcon,
  Curated,
  Empty,
  ErrorNotice,
  Metric,
  Metrics,
  Page,
  Pill,
  Sheet,
  Status,
} from "@mws-dashboard/ui";
import {
  BellOff,
  BellRing,
  CircleCheck,
  FileSearch,
  GitMerge,
  LayoutDashboard,
  Siren,
  Trash2,
} from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { AlarmForm, CompositeForm } from "../../lib/alarm-form";
import { formOptions, rule } from "../../lib/alarms";
import { Tail } from "../../lib/live";
import {
  ALARM_TONE,
  ICONS,
  alarmHref,
  listAlarms,
  sourceIcon,
} from "../../lib/clients";
import {
  deleteAlarm,
  saveAlarm,
  saveComposite,
  setActions,
  setState,
} from "./actions";

export const metadata: Metadata = { title: "Alarms" };

const STATES = [
  { id: "ALARM", title: "In alarm" },
  { id: "INSUFFICIENT_DATA", title: "Insufficient data" },
  { id: "OK", title: "OK" },
];

export default async function Alarms() {
  const [alarms, options] = await Promise.all([
    load(listAlarms),
    formOptions(),
  ]);
  const taken = alarms.ok ? alarms.value.map((a) => a.AlarmName!) : [];
  const newAlarm = (
    <Sheet title="New alarm" label="Create alarm" testId="create-alarm">
      <AlarmForm
        {...options}
        taken={taken}
        action={saveAlarm.bind(null, null)}
        testId="create-alarm"
      />
    </Sheet>
  );
  const create = (
    <>
      {newAlarm}
      <Sheet
        title="New composite alarm"
        label="Create composite alarm"
        icon={<GitMerge size={16} />}
        testId="create-composite"
      >
        <CompositeForm
          taken={taken}
          alarms={taken}
          topics={options.topics}
          topicArn={options.topicArn}
          action={saveComposite.bind(null, null)}
          testId="create-composite"
        />
      </Sheet>
      <Link
        className="icon-button plain"
        href="/dashboards"
        aria-label="Dashboards"
        title="Dashboards"
      >
        <LayoutDashboard size={16} aria-hidden />
      </Link>
    </>
  );
  if (!alarms.ok) {
    return (
      <Page title="Alarms" actions={create}>
        <ErrorNotice error={alarms.error} />
      </Page>
    );
  }
  const list = alarms.value;
  const count = (s: string) => list.filter((a) => a.StateValue === s).length;
  return (
    <Page title="Alarms" actions={create}>
      {/* The evaluator flips states on the emulated clock: keep them current. */}
      {list.length > 0 && <Tail every={10_000} />}
      {list.length > 0 && (
        <Metrics>
          <Metric
            label="In alarm"
            value={count("ALARM")}
            tone={count("ALARM") ? "bad" : undefined}
            icon={<Siren size={14} />}
          />
          <Metric label="Insufficient" value={count("INSUFFICIENT_DATA")} />
          <Metric
            label="OK"
            value={count("OK")}
            tone="good"
            icon={<CircleCheck size={14} />}
          />
        </Metrics>
      )}
      <Curated
        label="Alarms"
        sections={STATES.map((s) => ({
          ...s,
          items: list.filter((a) => a.StateValue === s.id),
        }))}
        empty={<Empty icon={ICONS.alarm} action={newAlarm} />}
        row={(a) => {
          const icon =
            a.kind === "metric" && a.Namespace
              ? sourceIcon(a.Namespace)
              : undefined;
          const name = a.AlarmName!;
          return {
            key: a.AlarmArn!,
            icon: <AwsIcon icon={icon ?? ICONS.alarm} size={22} />,
            title: name,
            subtitle: rule(a),
            href: alarmHref(name),
            meta: (
              <>
                {a.kind === "composite" && (
                  <Pill icon={<GitMerge size={12} />}>Composite</Pill>
                )}
                {a.kind === "log" && (
                  <Pill icon={<FileSearch size={12} />}>Logs</Pill>
                )}
                {!a.ActionsEnabled && (
                  <BellOff size={14} aria-label="Actions muted" />
                )}
                <Status tone={ALARM_TONE[a.StateValue ?? ""] ?? "neutral"}>
                  {ago(a.StateUpdatedTimestamp)}
                </Status>
              </>
            ),
            actions: (
              <>
                {a.StateValue !== "ALARM" ? (
                  <ActionForm
                    action={setState.bind(null, name, "ALARM")}
                    submit={`Set ${name} to ALARM`}
                    icon={<Siren size={15} />}
                  />
                ) : (
                  <ActionForm
                    action={setState.bind(null, name, "OK")}
                    submit={`Set ${name} to OK`}
                    icon={<CircleCheck size={15} />}
                  />
                )}
                <ActionForm
                  action={setActions.bind(null, name, !a.ActionsEnabled)}
                  submit={a.ActionsEnabled ? `Mute ${name}` : `Unmute ${name}`}
                  icon={
                    a.ActionsEnabled ? (
                      <BellOff size={15} />
                    ) : (
                      <BellRing size={15} />
                    )
                  }
                />
                <ActionForm
                  action={deleteAlarm.bind(null, name, false)}
                  submit={`Delete ${name}`}
                  icon={<Trash2 size={15} />}
                  tone="danger"
                  confirm={`Delete ${name}?`}
                />
              </>
            ),
          };
        }}
      />
    </Page>
  );
}

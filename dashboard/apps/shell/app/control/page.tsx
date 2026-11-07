import { ago, load, mws, when } from "@mws-dashboard/aws";
import { ActionForm, ErrorNotice, Field, List, Metric, Metrics, Page, Section, Sheet } from "@mws-dashboard/ui";
import { Camera, Clock, Download, FastForward, History, RotateCcw, Trash2, Upload } from "lucide-react";
import type { Metadata } from "next";

import { advanceClock, deleteSnapshot, importState, reset, resetClock, restoreSnapshot, saveSnapshot } from "./actions";

export const metadata: Metadata = { title: "Control plane" };

interface Snapshot {
  name: string;
  createdAt: string;
}

function duration(seconds: number) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return [d && `${d}d`, h && `${h}h`, m && `${m}m`, !d && !h && !m && `${seconds}s`].filter(Boolean).join(" ");
}

export default async function ControlPlane() {
  const [clock, snapshots, health] = await Promise.all([
    load(() => mws<{ now: string; offsetSeconds: number }>("/_mws/clock")),
    load(() => mws<{ snapshots: Snapshot[] }>("/_mws/snapshots")),
    load(() => mws<{ services: string[] }>("/_mws/health")),
  ]);
  const offset = clock.ok ? clock.value.offsetSeconds : 0;
  return (
    <Page
      title="Control plane"
      actions={
        <>
          <a className="icon-button" href="/control/state" download aria-label="Export state" title="Export state">
            <Download size={16} aria-hidden />
          </a>
          <Sheet title="Import state" label="Import state" icon={<Upload size={15} aria-hidden />}>
            <ActionForm action={importState} submit="Replace state" tone="danger" confirm="Replace all current state?">
              <input type="file" name="state" accept="application/json,.json" required />
            </ActionForm>
          </Sheet>
          <Sheet title="Reset" label="Reset" icon={<RotateCcw size={15} aria-hidden />}>
            <ActionForm action={reset} submit="Reset" tone="danger" confirm="Reset the emulator? Current state is lost.">
              <Field label="Back to">
                <select name="to" defaultValue="baseline">
                  <option value="baseline">Baseline (startup scenario)</option>
                  <option value="empty">Empty</option>
                </select>
              </Field>
            </ActionForm>
          </Sheet>
        </>
      }
    >
      <Metrics>
        <Metric
          icon={<Clock size={14} aria-hidden />}
          label={offset ? `+${duration(offset)}` : "Real time"}
          value={<span data-testid="clock-now">{clock.ok ? when(clock.value.now).slice(0, 16) : "—"}</span>}
          tone={offset ? "warn" : undefined}
        />
        <Metric label="Services" value={health.ok ? health.value.services.length : "—"} />
        <Metric label="Snapshots" value={snapshots.ok ? snapshots.value.snapshots.length : "—"} />
      </Metrics>
      {!clock.ok && <ErrorNotice error={clock.error} />}

      <Section title="Clock">
        <div className="form-row">
          <ActionForm action={advanceClock} submit="Advance" inline testId="advance-clock">
            <Field label="By">
              <input name="amount" type="number" min="1" step="any" defaultValue="1" required />
            </Field>
            <Field label="Unit">
              <select name="unit" defaultValue="hours">
                <option>seconds</option>
                <option>minutes</option>
                <option>hours</option>
                <option>days</option>
              </select>
            </Field>
          </ActionForm>
          {offset !== 0 && (
            <ActionForm action={resetClock} submit="Back to real time" icon={<History size={16} aria-hidden />} tone="plain" />
          )}
        </div>
      </Section>

      <Section
        title="Snapshots"
        plain
        actions={
          <Sheet title="Save snapshot" label="Save snapshot" icon={<Camera size={15} aria-hidden />} testId="save-snapshot">
            <ActionForm action={saveSnapshot} submit="Save" testId="save-snapshot">
              <Field label="Name">
                <input name="name" pattern="[A-Za-z0-9._\-]{1,128}" required />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {snapshots.ok ? (
          <List
            label="Snapshots"
            rows={snapshots.value.snapshots.map((s) => ({
              key: s.name,
              icon: <Camera size={18} aria-hidden />,
              title: s.name,
              meta: ago(s.createdAt),
              actions: (
                <>
                  <ActionForm
                    action={restoreSnapshot.bind(null, s.name)}
                    submit={`Restore ${s.name}`}
                    icon={<FastForward size={16} aria-hidden />}
                    confirm={`Replace the current state with ${s.name}?`}
                  />
                  <ActionForm
                    action={deleteSnapshot.bind(null, s.name)}
                    submit={`Delete ${s.name}`}
                    icon={<Trash2 size={16} aria-hidden />}
                    tone="danger"
                    confirm={`Delete snapshot ${s.name}?`}
                  />
                </>
              ),
            }))}
          />
        ) : (
          <ErrorNotice error={snapshots.error} />
        )}
      </Section>
    </Page>
  );
}

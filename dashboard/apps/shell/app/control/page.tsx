import { load, mws, when } from "@mws-dashboard/aws";
import { ActionForm, Badge, ErrorNotice, Field, KeyValue, PageHeader, Section, Table } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { advanceClock, deleteSnapshot, importState, reset, resetClock, restoreSnapshot, saveSnapshot } from "./actions";

export const metadata: Metadata = { title: "Control plane" };

interface Snapshot {
  name: string;
  createdAt: string;
}

export default async function ControlPlane() {
  const [clock, snapshots] = await Promise.all([
    load(() => mws<{ now: string; offsetSeconds: number }>("/_mws/clock")),
    load(() => mws<{ snapshots: Snapshot[] }>("/_mws/snapshots")),
  ]);
  return (
    <>
      <PageHeader
        title="Control plane"
        description="MWS's own control API (/_mws): move the emulated clock, save and restore snapshots, reset, and move state between machines."
      />
      <Section title="Emulated clock">
        {clock.ok ? (
          <KeyValue
            items={[
              ["Now", <span data-testid="clock-now">{when(clock.value.now)}</span>],
              [
                "Offset",
                clock.value.offsetSeconds === 0 ? (
                  <Badge>real time</Badge>
                ) : (
                  <Badge tone="info">+{clock.value.offsetSeconds}s</Badge>
                ),
              ],
            ]}
          />
        ) : (
          <ErrorNotice error={clock.error} />
        )}
        <p className="muted">
          Lifecycle rules, alarms, certificate expiry, Firehose buffers and other timers follow this clock. It only moves
          forward.
        </p>
        <div className="form-row">
          <ActionForm action={advanceClock} submit="Advance clock" inline testId="advance-clock">
            <Field label="Amount">
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
          <ActionForm action={resetClock} submit="Back to real time" tone="danger" inline />
        </div>
      </Section>

      <Section title="Snapshots">
        <ActionForm action={saveSnapshot} submit="Save snapshot" inline testId="save-snapshot">
          <Field label="Name" hint="Letters, digits, - _ and .">
            <input name="name" pattern="[A-Za-z0-9._\-]{1,128}" required />
          </Field>
        </ActionForm>
        <div style={{ marginTop: 12 }}>
          {snapshots.ok ? (
            <Table
              label="Snapshots"
              rows={snapshots.value.snapshots}
              rowKey={(s) => s.name}
              empty="No snapshots. Save one to come back to this exact state later."
              columns={[
                { header: "Name", cell: (s) => <code>{s.name}</code> },
                { header: "Saved", cell: (s) => when(s.createdAt) },
                {
                  header: "",
                  className: "actions-cell",
                  cell: (s) => (
                    <div className="actions-cell">
                      <ActionForm action={restoreSnapshot.bind(null, s.name)} submit="Restore" inline />
                      <ActionForm
                        action={deleteSnapshot.bind(null, s.name)}
                        submit="Delete"
                        tone="danger"
                        confirm={`Delete snapshot ${s.name}?`}
                        inline
                      />
                    </div>
                  ),
                },
              ]}
            />
          ) : (
            <ErrorNotice error={snapshots.error} />
          )}
        </div>
      </Section>

      <Section title="State">
        <p className="muted">
          Export every service&apos;s state as one JSON document, or replace the current state with one.
        </p>
        <div className="form-row">
          <a className="button primary" href="/control/state" download>
            Export state
          </a>
          <ActionForm action={importState} submit="Import state" inline confirm="Replace all current state?">
            <input type="file" name="state" accept="application/json,.json" required />
          </ActionForm>
        </div>
      </Section>

      <Section title="Reset">
        <ActionForm action={reset} submit="Reset" tone="danger" confirm="Reset the emulator? Current state is lost." inline>
          <Field label="Back to">
            <select name="to" defaultValue="baseline">
              <option value="baseline">the baseline (startup scenario)</option>
              <option value="empty">a fresh, empty emulator</option>
            </select>
          </Field>
        </ActionForm>
      </Section>
    </>
  );
}

import { ActionForm, Field, Sheet } from "@mws-dashboard/ui";
import { Copy, History, RotateCcw } from "lucide-react";

import { identifier } from "../../lib/rules";
import { copySnapshot, restorePointInTime, restoreSnapshot } from "./actions";

const ID = identifier(63);
const SNAPSHOT = identifier(255);

function ClassField({ classes, list, cluster, defaultValue }: { classes: string[]; list: string; cluster?: boolean; defaultValue?: string }) {
  return (
    <>
      <Field label={cluster ? "Writer instance class" : "Instance class"} rule={classes.length ? { enum: classes, ...(cluster ? { required: true } : {}) } : undefined}>
        <input name="class" list={list} defaultValue={defaultValue ?? (cluster ? "db.t4g.medium" : "")} placeholder={cluster ? undefined : "Same as the snapshot"} spellCheck={false} autoComplete="off" />
      </Field>
      <datalist id={list}>
        {classes.map((c) => (
          <option key={c} value={c} />
        ))}
      </datalist>
    </>
  );
}

/** Restore a snapshot to a new database (AWS: Actions → Restore snapshot). */
export function RestoreSnapshot({ kind, id, engine, classes, taken }: { kind: "instance" | "cluster"; id: string; engine: string; classes: string[]; taken: string[] }) {
  const testId = `restore-${id}`;
  return (
    <Sheet title={`Restore ${id}`} label={`Restore ${id}`} icon={<RotateCcw size={15} />} testId={testId}>
      <ActionForm action={restoreSnapshot.bind(null, kind, id, engine)} submit="Restore DB" testId={testId}>
        <Field label="DB identifier" rule={ID} taken={taken} unique>
          <input name="id" required autoFocus spellCheck={false} defaultValue={`${id}-restored`.slice(0, 63)} />
        </Field>
        <ClassField classes={classes} list={`${testId}-classes`} cluster={kind === "cluster"} />
      </ActionForm>
    </Sheet>
  );
}

export function CopySnapshot({ kind, id, taken }: { kind: "instance" | "cluster"; id: string; taken: string[] }) {
  const testId = `copy-${id}`;
  return (
    <Sheet title={`Copy ${id}`} label={`Copy ${id}`} icon={<Copy size={15} />} testId={testId}>
      <ActionForm action={copySnapshot.bind(null, kind, id)} submit="Copy snapshot" testId={testId}>
        <Field label="New snapshot name" rule={SNAPSHOT} taken={taken} unique>
          <input name="name" required autoFocus spellCheck={false} defaultValue={`${id}-copy`.slice(0, 255)} />
        </Field>
      </ActionForm>
    </Sheet>
  );
}

const local = (d: Date) => d.toISOString().slice(0, 19);

/** Restore to a point in time within the backup retention window. */
export function RestorePointInTime({
  kind,
  source,
  engine,
  classes,
  taken,
  earliest,
  latest,
}: {
  kind: "instance" | "cluster";
  source: string;
  engine: string;
  classes: string[];
  taken: string[];
  earliest?: Date;
  latest?: Date;
}) {
  return (
    <Sheet title="Restore to point in time" label="Restore to point in time" icon={<History size={16} />} testId="restore-pitr">
      <ActionForm action={restorePointInTime.bind(null, kind, source, engine)} submit="Restore" testId="restore-pitr">
        <Field label="DB identifier" rule={ID} taken={taken} unique>
          <input name="id" required autoFocus spellCheck={false} defaultValue={`${source}-pitr`.slice(0, 63)} />
        </Field>
        <div className="form-row">
          <Field label="Restore to">
            <select name="when" defaultValue="latest">
              <option value="latest">Latest restorable time{latest ? ` (${latest.toISOString().slice(0, 19).replace("T", " ")} UTC)` : ""}</option>
              <option value="custom">Custom (UTC)</option>
            </select>
          </Field>
          <Field label="Date and time (UTC)" hint={earliest ? `From ${earliest.toISOString().slice(0, 19).replace("T", " ")}` : undefined}>
            <input name="time" type="datetime-local" step={1} min={earliest ? local(earliest) : undefined} max={latest ? local(latest) : undefined} defaultValue={latest ? local(latest) : undefined} />
          </Field>
        </div>
        <ClassField classes={classes} list="pitr-classes" cluster={kind === "cluster"} />
      </ActionForm>
    </Sheet>
  );
}

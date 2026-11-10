import { ActionForm, Field, Sheet } from "@mws-dashboard/ui";
import { Copy, RotateCcw } from "lucide-react";

import type { Snap } from "../../lib/elasticache";
import { NAME, SNAPSHOT } from "../../lib/rules";
import { copySnapshot, restoreSnapshot } from "./actions";

/** Restore a snapshot into a new cache (AWS: Actions → Restore). */
export function RestoreSnapshot({ snap, taken, types }: { snap: Snap; taken: string[]; types: string[] }) {
  const testId = `restore-${snap.name}`;
  return (
    <Sheet title={`Restore ${snap.name}`} label={`Restore ${snap.name}`} icon={<RotateCcw size={15} />} testId={testId}>
      <ActionForm
        action={restoreSnapshot.bind(null, snap.kind, { name: snap.name, arn: snap.arn, engine: snap.engine, nodeType: snap.nodeType, shards: snap.shards })}
        submit="Restore"
        testId={testId}
      >
        <Field label="New cache name" rule={{ ...NAME, required: true }} taken={taken} unique>
          <input name="name" required autoFocus spellCheck={false} defaultValue={`${snap.name}-restored`.slice(0, 40).replace(/-+$/, "")} />
        </Field>
        {snap.kind === "node" && (
          <>
            <Field label="Node type" rule={types.length ? { enum: types } : undefined}>
              <input name="nodeType" defaultValue={snap.nodeType} list={`${testId}-types`} autoComplete="off" />
            </Field>
            <datalist id={`${testId}-types`}>
              {types.map((t) => (
                <option key={t} value={t} />
              ))}
            </datalist>
          </>
        )}
      </ActionForm>
    </Sheet>
  );
}

export function CopySnapshot({ kind, name, taken }: { kind: "node" | "serverless"; name: string; taken: string[] }) {
  const testId = `copy-${name}`;
  return (
    <Sheet title={`Copy ${name}`} label={`Copy ${name}`} icon={<Copy size={15} />} testId={testId}>
      <ActionForm action={copySnapshot.bind(null, kind, name)} submit="Copy" testId={testId}>
        <Field label="New snapshot name" rule={SNAPSHOT} taken={taken} unique>
          <input name="snapshot" required autoFocus spellCheck={false} defaultValue={`${name}-copy`} />
        </Field>
      </ActionForm>
    </Sheet>
  );
}

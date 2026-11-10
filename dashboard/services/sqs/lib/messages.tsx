"use client";

// Poll for messages, as the AWS console does: what came back, with each
// message's receive count (every receive counts toward the redrive policy's
// maxReceiveCount), and per-message delete and return for messages still
// held by this poll.

import { LoaderCircle, Search, Trash2, Undo2 } from "lucide-react";
import { useActionState, useState, useTransition } from "react";

import type { ActionResult } from "@mws-dashboard/ui";

import type { PollResult } from "../routes/sqs/actions";

type Poll = (previous: PollResult | null, form: FormData) => Promise<PollResult>;
type One = (receipt: string) => Promise<ActionResult>;

const time = (ms?: string) => (ms ? new Date(Number(ms)).toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z") : "");

export function Messages({ poll, remove, release, maxReceives }: { poll: Poll; remove: One; release: One; maxReceives?: number }) {
  const [state, run, pending] = useActionState(poll, null);
  const [done, setDone] = useState<Record<string, string>>({});
  const [busy, start] = useTransition();
  const act = (receipt: string, fn: One, label: string) =>
    start(async () => {
      const r = await fn(receipt);
      setDone((d) => ({ ...d, [receipt]: r.ok ? label : r.message }));
    });
  return (
    <form
      action={(form) => {
        setDone({});
        run(form);
      }}
      className="action-form"
      data-testid="receive-messages"
      data-state={pending ? "pending" : "idle"}
    >
      <div className="form-row">
        <select name="mode" defaultValue="peek" aria-label="Mode">
          <option value="peek">Poll and release</option>
          <option value="poll">Poll and hold</option>
          <option value="delete">Receive and delete</option>
        </select>
        <div className="form-actions">
          <button type="submit" className="button primary" disabled={pending}>
            <span>Poll</span>
            <span className="button-glyph">{pending ? <LoaderCircle className="spin" size={15} aria-hidden /> : <Search size={15} aria-hidden />}</span>
          </button>
        </div>
      </div>
      {state && !pending && (
        <div className={state.ok ? "result ok" : "result error"} role="status">
          <span>{state.message}</span>
          {state.messages && state.messages.length > 0 && (
            <div className="table-wrap">
              <table aria-label="Messages">
                <thead>
                  <tr>
                    <th>Body</th>
                    <th>Receives</th>
                    <th>Sent</th>
                    <th>Attributes</th>
                    {state.mode === "poll" && <th />}
                  </tr>
                </thead>
                <tbody>
                  {state.messages.map((m) => (
                    <tr key={m.id}>
                      <td>
                        <pre className="code">{m.body}</pre>
                        <code className="muted">{m.id}</code>
                        {m.group && <code className="muted"> · {m.group}</code>}
                      </td>
                      <td className={maxReceives && m.receives >= maxReceives ? "tone-bad" : maxReceives && m.receives >= maxReceives - 1 ? "tone-warn" : undefined} title={maxReceives ? `Moves to the dead-letter queue after ${maxReceives}` : undefined}>
                        {m.receives}
                        {maxReceives ? ` / ${maxReceives}` : ""}
                      </td>
                      <td>{time(m.sent)}</td>
                      <td>
                        {Object.entries(m.attributes).map(([k, v]) => (
                          <div key={k}>
                            <code>{k}</code>={v}
                          </div>
                        ))}
                      </td>
                      {state.mode === "poll" && (
                        <td>
                          {done[m.receipt] ? (
                            <span className="muted">{done[m.receipt]}</span>
                          ) : (
                            <span className="chips">
                              <button type="button" className="icon-button plain" aria-label={`Return ${m.id} to the queue`} title="Return to queue" disabled={busy} onClick={() => act(m.receipt, release, "Returned")}>
                                <Undo2 size={15} aria-hidden />
                              </button>
                              <button type="button" className="icon-button danger" aria-label={`Delete ${m.id}`} title="Delete" disabled={busy} onClick={() => act(m.receipt, remove, "Deleted")}>
                                <Trash2 size={15} aria-hidden />
                              </button>
                            </span>
                          )}
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </form>
  );
}

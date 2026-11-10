import { DescribeArchiveCommand } from "@aws-sdk/client-eventbridge";
import { ago, bytes, load } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, Empty, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Status } from "@mws-dashboard/ui";
import { Archive, History, Settings2, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { events } from "../../../lib/clients";
import { ARCHIVE_DESCRIPTION, ARCHIVE_NAME, PATTERN, REPLAY_NAME, RETENTION } from "../../../lib/rules";
import { archives, buses } from "../../../lib/targets";
import { EventsTabs } from "../../../lib/tabs";
import { createArchive, deleteArchive, startReplay, updateArchive } from "../actions";

export const metadata: Metadata = { title: "Archives" };

type Props = { searchParams: Promise<{ archive?: string }> };

const local = (d: Date) => new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);

export default async function Archives({ searchParams }: Props) {
  const focus = (await searchParams).archive;
  const [list, busList] = await Promise.all([load(archives), load(buses)]);
  const busArns = busList.ok ? busList.value.map((b) => b.Arn!) : [];
  const client = await events();
  const details = list.ok
    ? await Promise.all(list.value.map((a) => client.send(new DescribeArchiveCommand({ ArchiveName: a.ArchiveName! })).catch(() => undefined)))
    : [];
  const now = new Date();
  return (
    <Page
      title="Archives"
      actions={
        <Sheet title="New archive" label="Create archive" testId="create-archive">
          <ActionForm action={createArchive} submit="Create" testId="create-archive">
            <Field label="Name" rule={ARCHIVE_NAME} taken={list.ok ? list.value.map((a) => a.ArchiveName!) : []} unique member="ArchiveName">
              <input name="name" required autoFocus spellCheck={false} />
            </Field>
            <Field label="Source bus">
              <select name="source" required defaultValue={busArns.find((a) => a.endsWith("/default"))}>
                {busArns.map((a) => (
                  <option key={a} value={a}>
                    {a.split("/").pop()}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Description" rule={ARCHIVE_DESCRIPTION}>
              <input name="description" />
            </Field>
            <Field label="Event pattern" rule={{ ...PATTERN, required: false }} format="eventPattern" member="EventPattern">
              <textarea name="pattern" rows={4} placeholder="All events" spellCheck={false} />
            </Field>
            <Field label="Retention (days)" rule={RETENTION} member="RetentionDays">
              <input name="retention" inputMode="numeric" placeholder="Indefinitely" />
            </Field>
          </ActionForm>
        </Sheet>
      }
    >
      <EventsTabs active="archives" />
      {list.ok ? (
        <List
          label="Archives"
          empty={<Empty icon="service/AmazonEventBridge" />}
          rows={list.value.map((a, i) => {
            const d = details[i];
            const bus = a.EventSourceArn?.split("/").pop();
            return {
              key: a.ArchiveName!,
              icon: <Archive size={18} aria-hidden />,
              title: a.ArchiveName === focus ? <strong>{a.ArchiveName}</strong> : a.ArchiveName,
              subtitle: (
                <>
                  <Link href={bus === "default" ? "/events" : `/events?bus=${encodeURIComponent(bus ?? "")}`}>{bus}</Link>
                  {d?.Description && <> · {d.Description}</>}
                  {d?.EventPattern && (
                    <details>
                      <summary>pattern</summary>
                      <CodeBlock value={d.EventPattern} />
                    </details>
                  )}
                </>
              ),
              meta: (
                <>
                  <Pill title="Events">{a.EventCount ?? 0} events</Pill>
                  {a.SizeBytes ? <span>{bytes(a.SizeBytes)}</span> : null}
                  <Pill title="Retention">{a.RetentionDays ? `${a.RetentionDays}d` : "∞"}</Pill>
                  {a.State && a.State !== "ENABLED" && <Status tone={/FAILED/.test(a.State) ? "bad" : "info"}>{a.State}</Status>}
                  <span>{ago(a.CreationTime)}</span>
                </>
              ),
              actions: (
                <>
                  <Sheet title={`Replay from ${a.ArchiveName}`} label={`Start replay from ${a.ArchiveName}`} icon={<History size={15} aria-hidden />} testId="start-replay">
                    <ActionForm action={startReplay} submit="Start replay" testId="start-replay">
                      <input type="hidden" name="archive" value={d?.ArchiveArn ?? ""} />
                      <Field label="Name" rule={REPLAY_NAME} member="ReplayName">
                        <input name="name" required defaultValue={`${a.ArchiveName}-${now.getTime().toString(36)}`.slice(0, 64)} spellCheck={false} />
                      </Field>
                      <div className="form-row">
                        <Field label="Start">
                          <input name="start" type="datetime-local" required defaultValue={local(new Date(Math.max(new Date(a.CreationTime ?? now).getTime(), now.getTime() - 86_400_000)))} />
                        </Field>
                        <Field label="End">
                          <input name="end" type="datetime-local" required defaultValue={local(now)} />
                        </Field>
                      </div>
                      <Field label="Destination bus">
                        <select name="destination" defaultValue={a.EventSourceArn}>
                          {busArns.map((b) => (
                            <option key={b} value={b}>
                              {b.split("/").pop()}
                            </option>
                          ))}
                        </select>
                      </Field>
                    </ActionForm>
                  </Sheet>
                  <Sheet title={`Archive ${a.ArchiveName}`} label={`Edit ${a.ArchiveName}`} icon={<Settings2 size={15} aria-hidden />} testId="edit-archive">
                    <ActionForm action={updateArchive.bind(null, a.ArchiveName!)} submit="Save" testId="edit-archive">
                      <Field label="Description" rule={ARCHIVE_DESCRIPTION}>
                        <input name="description" defaultValue={d?.Description} />
                      </Field>
                      <Field label="Event pattern" rule={{ ...PATTERN, required: false }} format="eventPattern">
                        <textarea name="pattern" rows={4} spellCheck={false} defaultValue={d?.EventPattern ? JSON.stringify(JSON.parse(d.EventPattern), null, 2) : ""} />
                      </Field>
                      <Field label="Retention (days)" rule={RETENTION}>
                        <input name="retention" inputMode="numeric" defaultValue={a.RetentionDays || undefined} />
                      </Field>
                    </ActionForm>
                  </Sheet>
                  <ActionForm action={deleteArchive.bind(null, a.ArchiveName!)} submit={`Delete ${a.ArchiveName}`} icon={<Trash2 size={15} aria-hidden />} tone="danger" confirm={`Delete archive ${a.ArchiveName}?`} />
                </>
              ),
            };
          })}
        />
      ) : (
        <ErrorNotice error={list.error} />
      )}
      {!busList.ok && (
        <Section>
          <ErrorNotice error={busList.error} />
        </Section>
      )}
    </Page>
  );
}

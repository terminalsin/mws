import { sections } from "@mws-dashboard/ai";
import { ago, bytes, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Metric, Metrics, Page, Pill, Sheet } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { GROUP_KINDS, ICONS, groupHref, listGroups, sourceIcon } from "../../lib/clients";
import { RETENTION, retentionLabel } from "../../lib/retention";
import { createGroup } from "./actions";

export const metadata: Metadata = { title: "Logs" };

type Props = { searchParams: Promise<{ prefix?: string }> };

export default async function LogGroups({ searchParams }: Props) {
  const prefix = (await searchParams).prefix ?? "";
  const groups = await load(() => listGroups(prefix));
  const create = (
    <Sheet title="New log group" label="Create log group" testId="create-log-group">
      <ActionForm action={createGroup} submit="Create" testId="create-log-group">
        <Field label="Name">
          <input name="name" required placeholder="/app/api" autoFocus />
        </Field>
        <Field label="Retention">
          <select name="retention" defaultValue="0">
            {RETENTION.map((d) => (
              <option key={d} value={d}>
                {retentionLabel(d)}
              </option>
            ))}
          </select>
        </Field>
        <label className="check">
          <input type="checkbox" name="infrequent" /> Infrequent Access
        </label>
      </ActionForm>
    </Sheet>
  );
  if (!groups.ok) {
    return (
      <Page title="Logs" icon={ICONS.cloudwatch} actions={create}>
        <ErrorNotice error={groups.error} />
      </Page>
    );
  }
  const items = groups.value.map((g) => ({ ...g, text: g.logGroupName! }));
  const grouped = await sections(items, GROUP_KINDS, "Applications");
  const stored = groups.value.reduce((n, g) => n + (g.storedBytes ?? 0), 0);
  const forever = groups.value.filter((g) => !g.retentionInDays).length;
  return (
    <Page title="Logs" icon={ICONS.cloudwatch} actions={create}>
      {groups.value.length > 0 && (
        <Metrics>
          <Metric label="Log groups" value={groups.value.length} />
          <Metric label="Stored" value={bytes(stored)} />
          {forever > 0 && <Metric label="Kept forever" value={forever} tone="warn" />}
        </Metrics>
      )}
      <form className="search-page-form" action="/observability/logs">
        <input name="prefix" defaultValue={prefix} placeholder="Prefix" aria-label="Log group prefix" />
      </form>
      <Curated
        label="Log groups"
        sections={grouped}
        empty={<Empty icon={ICONS.logs} />}
        row={(g) => ({
          key: g.logGroupArn ?? g.logGroupName!,
          icon: <AwsIcon icon={sourceIcon(g.logGroupName!) ?? ICONS.logs} size={22} />,
          title: g.logGroupName,
          href: groupHref(g.logGroupName!),
          meta: (
            <>
              {g.storedBytes ? <span>{bytes(g.storedBytes)}</span> : null}
              {g.retentionInDays ? <Pill>{retentionLabel(g.retentionInDays)}</Pill> : null}
              {g.logGroupClass === "INFREQUENT_ACCESS" && <Pill tone="info">IA</Pill>}
              <span>{ago(g.creationTime)}</span>
            </>
          ),
        })}
      />
    </Page>
  );
}

import { sections } from "@mws-dashboard/ai";
import { ago, bytes, load } from "@mws-dashboard/aws";
import {
  ActionForm,
  AwsIcon,
  Curated,
  Empty,
  ErrorNotice,
  Field,
  Metric,
  Metrics,
  Page,
  Pill,
  Sheet,
} from "@mws-dashboard/ui";
import {
  CreateLogGroup,
  DescribeLogGroups,
  PutRetentionPolicy,
} from "@mws-dashboard/ui/model/logs";
import { FileSearch, Shield } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import {
  GROUP_KINDS,
  ICONS,
  groupHref,
  listGroups,
  sourceIcon,
} from "../../lib/clients";
import { RETENTION, retentionLabel } from "../../lib/retention";
import { keyOptions } from "../../lib/destinations";
import { createGroup } from "./actions";

export const metadata: Metadata = { title: "Logs" };

type Props = { searchParams: Promise<{ prefix?: string }> };

export default async function LogGroups({ searchParams }: Props) {
  const prefix = (await searchParams).prefix ?? "";
  const [groups, keys] = await Promise.all([
    load(() => listGroups(prefix)),
    keyOptions(),
  ]);
  const taken = groups.ok ? groups.value.map((g) => g.logGroupName!) : [];
  const create = (
    <>
      <Link
        className="icon-button plain"
        href="/logs/insights"
        aria-label="Logs Insights"
        title="Logs Insights"
      >
        <FileSearch size={16} aria-hidden />
      </Link>
      <Sheet
        title="New log group"
        label="Create log group"
        testId="create-log-group"
      >
        <ActionForm
          action={createGroup}
          submit="Create"
          testId="create-log-group"
        >
          <Field
            label="Name"
            rule={CreateLogGroup.logGroupName}
            taken={taken}
            generate={{ prefix: "/app/" }}
            unique
          >
            <input name="name" placeholder="/app/api" autoFocus />
          </Field>
          <Field label="Retention" rule={PutRetentionPolicy.retentionInDays}>
            <select name="retention" defaultValue="0">
              {RETENTION.map((d) => (
                <option key={d} value={d}>
                  {retentionLabel(d)}
                </option>
              ))}
            </select>
          </Field>
          <Field
            label="KMS key ARN"
            rule={{ ...CreateLogGroup.kmsKeyId, format: "arn" }}
            known={keys.arns}
          >
            <input name="kms" list="create-kms-keys" />
          </Field>
          <datalist id="create-kms-keys">
            {Object.entries(keys.aliases).map(([alias, arn]) => (
              <option key={alias} value={arn}>
                {alias}
              </option>
            ))}
          </datalist>
          <Field label="Tags" rule={{ ...CreateLogGroup.tags, format: "tags" }}>
            <textarea name="tags" rows={1} placeholder="team=payments" />
          </Field>
          <label className="check">
            <input type="checkbox" name="infrequent" /> Infrequent Access
          </label>
          <label className="check">
            <input type="checkbox" name="protect" /> Deletion protection
          </label>
        </ActionForm>
      </Sheet>
    </>
  );
  if (!groups.ok) {
    return (
      <Page title="Log groups" actions={create}>
        <ErrorNotice error={groups.error} />
      </Page>
    );
  }
  const items = groups.value.map((g) => ({ ...g, text: g.logGroupName! }));
  const grouped = await sections(items, GROUP_KINDS, "Applications");
  const stored = groups.value.reduce((n, g) => n + (g.storedBytes ?? 0), 0);
  const forever = groups.value.filter((g) => !g.retentionInDays).length;
  return (
    <Page title="Log groups" actions={create}>
      {groups.value.length > 0 && (
        <Metrics>
          <Metric label="Log groups" value={groups.value.length} />
          <Metric label="Stored" value={bytes(stored)} />
          {forever > 0 && (
            <Metric label="Kept forever" value={forever} tone="warn" />
          )}
        </Metrics>
      )}
      <form className="search-page-form" action="/logs">
        <Field
          label="Prefix"
          rule={DescribeLogGroups.logGroupNamePrefix}
          known={taken}
        >
          <input
            name="prefix"
            defaultValue={prefix}
            placeholder="Prefix"
            aria-label="Log group prefix"
          />
        </Field>
      </form>
      <Curated
        label="Log groups"
        sections={grouped}
        empty={<Empty icon={ICONS.logs} />}
        row={(g) => ({
          key: g.logGroupArn ?? g.logGroupName!,
          icon: (
            <AwsIcon
              icon={sourceIcon(g.logGroupName!) ?? ICONS.logs}
              size={22}
            />
          ),
          title: g.logGroupName,
          href: groupHref(g.logGroupName!),
          meta: (
            <>
              {g.storedBytes ? <span>{bytes(g.storedBytes)}</span> : null}
              {g.retentionInDays ? (
                <Pill>{retentionLabel(g.retentionInDays)}</Pill>
              ) : null}
              {g.logGroupClass === "INFREQUENT_ACCESS" && (
                <Pill tone="info">IA</Pill>
              )}
              {g.deletionProtectionEnabled && (
                <Shield size={14} aria-label="Deletion protection" />
              )}
              <span>{ago(g.creationTime)}</span>
            </>
          ),
        })}
      />
    </Page>
  );
}

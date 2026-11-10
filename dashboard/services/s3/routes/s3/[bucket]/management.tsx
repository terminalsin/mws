import { GetBucketLifecycleConfigurationCommand, GetBucketReplicationCommand, ListMultipartUploadsCommand, type LifecycleRule } from "@aws-sdk/client-s3";
import { ago, all, load, shortName } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, ErrorNotice, Field, FileIcon, List, Pill, Section, Sheet, Status } from "@mws-dashboard/ui";
import { Braces, Pause, Play, Plus, Trash2, X } from "lucide-react";
import Link from "next/link";

import { CONTROL_ICONS, bucketHref, links, optional, s3 } from "../../../lib/s3";
import { abortUpload, saveLifecycleJson, setLifecycleRule } from "../actions";
import { LifecycleRuleForm } from "./lifecycle-rule.tsx";

/** What a lifecycle rule does, in a line. */
function describeRule(r: LifecycleRule) {
  const parts = [
    ...(r.Transitions ?? []).map((t) => `${t.StorageClass} after ${t.Days ?? t.Date?.toISOString().slice(0, 10)}${t.Days != null ? "d" : ""}`),
    r.Expiration?.Days != null && `expire after ${r.Expiration.Days}d`,
    r.Expiration?.Date && `expire on ${r.Expiration.Date.toISOString().slice(0, 10)}`,
    r.Expiration?.ExpiredObjectDeleteMarker && "remove expired delete markers",
    ...(r.NoncurrentVersionTransitions ?? []).map((t) => `noncurrent to ${t.StorageClass} after ${t.NoncurrentDays}d`),
    r.NoncurrentVersionExpiration?.NoncurrentDays != null && `noncurrent expire after ${r.NoncurrentVersionExpiration.NoncurrentDays}d`,
    r.AbortIncompleteMultipartUpload?.DaysAfterInitiation != null && `abort uploads after ${r.AbortIncompleteMultipartUpload.DaysAfterInitiation}d`,
  ].filter(Boolean);
  return parts.join(" · ");
}

function scope(r: LifecycleRule) {
  const f = r.Filter;
  const prefix = f?.Prefix ?? f?.And?.Prefix ?? r.Prefix;
  const tags = [...(f?.Tag ? [f.Tag] : []), ...(f?.And?.Tags ?? [])].map((t) => `${t.Key}=${t.Value}`);
  return [prefix ? `${prefix}*` : "Whole bucket", ...tags].join(" · ");
}

export async function Management({ bucket }: { bucket: string }) {
  const client = await s3();
  const [lifecycle, replication, uploads] = await Promise.all([
    load(() => optional(() => client.send(new GetBucketLifecycleConfigurationCommand({ Bucket: bucket })))),
    load(() => optional(() => client.send(new GetBucketReplicationCommand({ Bucket: bucket })))),
    load(() =>
      all(
        (token) => {
          const [KeyMarker, UploadIdMarker] = token ? JSON.parse(token) : [undefined, undefined];
          return client.send(new ListMultipartUploadsCommand({ Bucket: bucket, KeyMarker, UploadIdMarker }));
        },
        (r) => r.Uploads,
        (r) => (r.IsTruncated ? JSON.stringify([r.NextKeyMarker, r.NextUploadIdMarker]) : undefined),
      ),
    ),
  ]);
  const rules = lifecycle.ok ? (lifecycle.value?.Rules ?? []) : [];
  const repl = replication.ok ? replication.value?.ReplicationConfiguration : undefined;
  return (
    <>
      <Section
        title="Lifecycle rules"
        count={rules.length}
        actions={
          <>
            <Sheet title="Create lifecycle rule" label="Create lifecycle rule" icon={<Plus size={15} aria-hidden />} testId="create-lifecycle-rule">
              <LifecycleRuleForm bucket={bucket} taken={rules.map((r) => r.ID!).filter(Boolean)} />
            </Sheet>
            <Sheet title="Lifecycle configuration" label="Edit lifecycle rules as JSON" icon={<Braces size={15} aria-hidden />} testId="edit-lifecycle">
              <ActionForm action={saveLifecycleJson.bind(null, bucket)} submit="Save" testId="edit-lifecycle">
                <Field label="Rules (JSON)" format="json" hint="Empty removes the configuration">
                  <textarea name="rules" rows={16} defaultValue={rules.length ? JSON.stringify(rules, null, 2) : ""} />
                </Field>
              </ActionForm>
            </Sheet>
          </>
        }
        plain
      >
        {!lifecycle.ok ? (
          <ErrorNotice error={lifecycle.error} />
        ) : (
          <List
            label="Lifecycle rules"
            empty={<span className="muted">None</span>}
            rows={rules.map((r, i) => ({
              key: r.ID ?? String(i),
              title: r.ID ?? `Rule ${i + 1}`,
              subtitle: `${scope(r)} · ${describeRule(r)}`,
              meta: <Status tone={r.Status === "Enabled" ? "good" : "neutral"}>{r.Status}</Status>,
              actions: r.ID ? (
                <>
                  <ActionForm
                    action={setLifecycleRule.bind(null, bucket, r.ID, r.Status !== "Enabled")}
                    submit={r.Status === "Enabled" ? `Disable ${r.ID}` : `Enable ${r.ID}`}
                    icon={r.Status === "Enabled" ? <Pause size={15} aria-hidden /> : <Play size={15} aria-hidden />}
                  />
                  <ActionForm action={setLifecycleRule.bind(null, bucket, r.ID, null)} submit={`Delete rule ${r.ID}`} icon={<Trash2 size={15} aria-hidden />} tone="danger" confirm={`Delete lifecycle rule ${r.ID}?`} />
                </>
              ) : undefined,
            }))}
          />
        )}
      </Section>
      <Section title="Replication rules" icon={<AwsIcon icon={CONTROL_ICONS.replication} size={16} />} count={repl?.Rules?.length ?? 0} plain>
        {!replication.ok ? (
          <ErrorNotice error={replication.error} />
        ) : repl ? (
          <>
            <List
              label="Replication rules"
              rows={(repl.Rules ?? []).map((r, i) => {
                const dest = r.Destination?.Bucket?.replace(/^arn:aws:s3:::/, "");
                return {
                  key: r.ID ?? String(i),
                  icon: <AwsIcon icon={CONTROL_ICONS.replication} size={22} />,
                  title: r.ID ?? `Rule ${i + 1}`,
                  subtitle: (
                    <>
                      {r.Filter?.Prefix ?? r.Prefix ? `${r.Filter?.Prefix ?? r.Prefix}* → ` : "→ "}
                      {dest ? <Link href={bucketHref(dest)}>{dest}</Link> : r.Destination?.Bucket}
                      {r.Destination?.StorageClass ? ` · ${r.Destination.StorageClass}` : ""}
                    </>
                  ),
                  meta: (
                    <>
                      {r.Priority != null && <Pill>Priority {r.Priority}</Pill>}
                      {r.DeleteMarkerReplication?.Status === "Enabled" && <Pill>Delete markers</Pill>}
                      <Status tone={r.Status === "Enabled" ? "good" : "neutral"}>{r.Status}</Status>
                    </>
                  ),
                };
              })}
            />
            {repl.Role && (
              <p className="muted">
                Role <Link href={links.role(repl.Role)}>{shortName(repl.Role)}</Link>
              </p>
            )}
            <details>
              <summary>Replication configuration</summary>
              <CodeBlock value={JSON.stringify(repl)} label="Replication configuration" />
            </details>
          </>
        ) : (
          <span className="muted">None</span>
        )}
      </Section>
      <Section title="Incomplete multipart uploads" count={uploads.ok ? uploads.value.length : undefined} plain>
        {!uploads.ok ? (
          <ErrorNotice error={uploads.error} />
        ) : (
          <List
            label="Multipart uploads"
            empty={<span className="muted">None</span>}
            rows={uploads.value.map((u) => ({
              key: u.UploadId!,
              icon: <FileIcon name={u.Key!} />,
              title: u.Key,
              subtitle: <code className="clip">{u.UploadId}</code>,
              meta: (
                <>
                  {u.StorageClass && u.StorageClass !== "STANDARD" && <Pill>{u.StorageClass}</Pill>}
                  <span title={u.Initiated?.toISOString()}>{ago(u.Initiated)}</span>
                </>
              ),
              actions: <ActionForm action={abortUpload.bind(null, bucket, u.Key!, u.UploadId!)} submit={`Abort upload of ${u.Key}`} icon={<X size={15} aria-hidden />} tone="danger" confirm={`Abort this upload of ${u.Key}? Its parts are deleted.`} />,
            }))}
          />
        )}
      </Section>
    </>
  );
}

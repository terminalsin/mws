import { ListBucketsCommand } from "@aws-sdk/client-s3";
import {
  DescribeJobCommand,
  GetAccessGrantsInstanceCommand,
  GetAccessPointConfigurationForObjectLambdaCommand,
  GetAccessPointForObjectLambdaCommand,
  GetAccessPointPolicyForObjectLambdaCommand,
  GetStorageLensConfigurationCommand,
  ListAccessGrantsCommand,
  ListAccessGrantsLocationsCommand,
  ListAccessPointsForObjectLambdaCommand,
  ListJobsCommand,
  ListMultiRegionAccessPointsCommand,
  ListStorageLensConfigurationsCommand,
  ListStorageLensGroupsCommand,
  type JobOperation,
} from "@aws-sdk/client-s3-control";
import { ago, all, load, shortName } from "@mws-dashboard/aws";
import { roleOptions } from "@mws-dashboard/aws/auto";
import { ActionForm, AutoPick, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Metric, Metrics, Pill, Section, Sheet, Status, type Rule } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { CreateAccessGrantsLocation, CreateAccessPointForObjectLambda, CreateMultiRegionAccessPoint, PutStorageLensConfiguration } from "@mws-dashboard/ui/model/s3control";
import { ruleAt } from "@mws-dashboard/ui/validation";
import { Check, Plus, Trash2, X } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { BATCH_ROLE, GRANTS_ROLE } from "../../lib/roles";
import { CONTROL_ICONS, account, bucketHref, control, controlHref, links, optional, s3 } from "../../lib/s3";
import { accessPoints } from "./access-points";
import { JobForm } from "./job-form.tsx";
import {
  createGrant,
  createGrantsInstance,
  createGrantsLocation,
  createLens,
  createMrap,
  createObjectLambda,
  deleteGrant,
  deleteGrantsInstance,
  deleteGrantsLocation,
  deleteLens,
  deleteLensGroup,
  deleteMrap,
  deleteObjectLambda,
  setJobPriority,
  setJobStatus,
} from "./control-actions";
import { BPA_SETTINGS } from "./[bucket]/permissions";

export const CONTROL_TABS: [string, string][] = [
  ["object-lambda", "Object Lambda Access Points"],
  ["multi-region", "Multi-Region Access Points"],
  ["batch", "Batch Operations"],
  ["access-grants", "Access Grants"],
  ["storage-lens", "Storage Lens"],
];

type View = { actions?: ReactNode; body: ReactNode; title?: string };

const bucketsOf = async () => ((await (await s3()).send(new ListBucketsCommand({}))).Buckets ?? []).map((b) => b.Name!);

export async function ControlTab({ tab, id }: { tab: string; id?: string }): Promise<View> {
  switch (tab) {
    case "object-lambda":
      return id ? objectLambdaDetail(id) : objectLambdas();
    case "multi-region":
      return mraps();
    case "batch":
      return id ? jobDetail(id) : jobs();
    case "access-grants":
      return grants();
    case "storage-lens":
      return id ? lensDetail(id) : lenses();
    default:
      return { body: <ErrorNotice error={`Unknown tab ${tab}`} /> };
  }
}

// --- Object Lambda ---------------------------------------------------------

const OLAP_NAME: Rule = { ...CreateAccessPointForObjectLambda.Name, hint: "Lowercase letters, digits and -", generate: "name" };

async function objectLambdas(): Promise<View> {
  const [list, points] = await Promise.all([
    load(async () => {
      const AccountId = await account();
      const client = await control();
      return all(
        (NextToken) => client.send(new ListAccessPointsForObjectLambdaCommand({ AccountId, NextToken })),
        (r) => r.ObjectLambdaAccessPointList,
        (r) => r.NextToken,
      );
    }),
    load(() => accessPoints()),
  ]);
  const actions = (
    <Sheet title="Create Object Lambda Access Point" label="Create Object Lambda Access Point" testId="create-object-lambda">
      <ActionForm action={createObjectLambda} submit="Create" testId="create-object-lambda">
        <Field label="Name" rule={OLAP_NAME} taken={list.ok ? list.value.map((o) => o.Name!) : []} unique>
          <input name="name" required autoFocus />
        </Field>
        <Field label="Supporting access point" rule={ruleAt(CreateAccessPointForObjectLambda, "Configuration.SupportingAccessPoint")}>
          <select name="supporting" required>
            {(points.ok ? points.value : []).map((p) => (
              <option key={p.AccessPointArn} value={p.AccessPointArn}>
                {p.Name} ({p.Bucket})
              </option>
            ))}
          </select>
        </Field>
        <Field label="Lambda function ARN" format="arn">
          <input name="function" required placeholder="arn:aws:lambda:us-east-1:123456789012:function:transform" />
        </Field>
        <fieldset className="field">
          <legend className="field-label">Also transform</legend>
          {["GetObject-Range", "GetObject-PartNumber", "HeadObject-Range", "HeadObject-PartNumber"].map((f) => (
            <label key={f} className="check">
              <input type="checkbox" name="features" value={f} /> {f}
            </label>
          ))}
        </fieldset>
        <label className="check">
          <input type="checkbox" name="metrics" /> CloudWatch request metrics
        </label>
      </ActionForm>
    </Sheet>
  );
  return {
    actions,
    body: !list.ok ? (
      <ErrorNotice error={list.error} />
    ) : (
      <List
        label="Object Lambda Access Points"
        empty={<Empty icon={CONTROL_ICONS.objectLambda} />}
        rows={list.value.map((o) => ({
          key: o.Name!,
          icon: <AwsIcon icon={CONTROL_ICONS.objectLambda} size={24} />,
          title: o.Name,
          subtitle: o.Alias?.Value,
          href: controlHref("object-lambda", { id: o.Name }),
          meta: o.Alias?.Status && <Status tone={o.Alias.Status === "READY" ? "good" : "warn"}>{o.Alias.Status}</Status>,
        }))}
      />
    ),
  };
}

async function objectLambdaDetail(name: string): Promise<View> {
  const data = await load(async () => {
    const AccountId = await account();
    const client = await control();
    const [ap, config, policy] = await Promise.all([
      client.send(new GetAccessPointForObjectLambdaCommand({ AccountId, Name: name })),
      client.send(new GetAccessPointConfigurationForObjectLambdaCommand({ AccountId, Name: name })),
      load(() => optional(() => client.send(new GetAccessPointPolicyForObjectLambdaCommand({ AccountId, Name: name })))),
    ]);
    return { ap, config: config.Configuration, policy };
  });
  const back = <Link href={controlHref("object-lambda")}>Object Lambda Access Points</Link>;
  if (!data.ok) return { title: name, body: <ErrorNotice error={data.error} /> };
  const { ap, config, policy } = data.value;
  const supporting = config?.SupportingAccessPoint;
  return {
    title: name,
    actions: <ActionForm action={deleteObjectLambda.bind(null, name)} submit="Delete Object Lambda Access Point" icon={<Trash2 size={16} aria-hidden />} tone="danger" confirm={`Delete ${name}?`} testId="delete-object-lambda" />,
    body: (
      <>
        <p>{back}</p>
        <Section title="Properties">
          <Facts
            items={[
              ["Alias", <code>{ap.Alias?.Value}</code>],
              ap.Alias?.Status && ["Status", <Status tone={ap.Alias.Status === "READY" ? "good" : "warn"}>{ap.Alias.Status}</Status>],
              supporting && ["Supporting access point", <code>{supporting}</code>],
              ...(config?.TransformationConfigurations ?? []).map((t) => {
                const fn = t.ContentTransformation?.AwsLambda?.FunctionArn ?? "";
                return [`${(t.Actions ?? []).join(", ")} via`, <Link href={links.lambda(fn)}>{shortName(fn)}</Link>] as [string, ReactNode];
              }),
              config?.AllowedFeatures?.length ? ["Also transforms", config.AllowedFeatures.join(", ")] : null,
              ["CloudWatch metrics", config?.CloudWatchMetricsEnabled ? "On" : "Off"],
              ["Created", ago(ap.CreationDate)],
            ]}
          />
        </Section>
        <Section title="Policy">{!policy.ok ? <ErrorNotice error={policy.error} /> : policy.value?.Policy ? <CodeBlock value={policy.value.Policy} label="Object Lambda Access Point policy" /> : <span className="muted">None</span>}</Section>
      </>
    ),
  };
}

// --- Multi-Region access points ------------------------------------------------

const MRAP_NAME: Rule = { ...ruleAt(CreateMultiRegionAccessPoint, "Details.Name"), hint: "Lowercase letters, digits and -", generate: "name" };

async function mraps(): Promise<View> {
  const [list, buckets] = await Promise.all([
    load(async () => {
      const AccountId = await account();
      const client = await control();
      return all(
        (NextToken) => client.send(new ListMultiRegionAccessPointsCommand({ AccountId, NextToken })),
        (r) => r.AccessPoints,
        (r) => r.NextToken,
      );
    }),
    load(bucketsOf),
  ]);
  const actions = (
    <Sheet title="Create Multi-Region Access Point" label="Create Multi-Region Access Point" testId="create-mrap">
      <ActionForm action={createMrap} submit="Create" testId="create-mrap">
        <Field label="Name" rule={MRAP_NAME} taken={list.ok ? list.value.map((m) => m.Name!) : []} unique>
          <input name="name" required autoFocus />
        </Field>
        <Field label="Buckets" hint="One per Region; hold ⌘/Ctrl to pick several">
          <select name="buckets" multiple required size={6}>
            {(buckets.ok ? buckets.value : []).map((b) => (
              <option key={b}>{b}</option>
            ))}
          </select>
        </Field>
        <fieldset className="field">
          <legend className="field-label">Block Public Access</legend>
          {BPA_SETTINGS.map(([k, label]) => (
            <label key={k} className="check">
              <input type="checkbox" name={k} defaultChecked /> {label}
            </label>
          ))}
        </fieldset>
      </ActionForm>
    </Sheet>
  );
  return {
    actions,
    body: !list.ok ? (
      <ErrorNotice error={list.error} />
    ) : (
      <List
        label="Multi-Region Access Points"
        empty={<Empty icon={CONTROL_ICONS.mrap} />}
        rows={list.value.map((m) => ({
          key: m.Name!,
          icon: <AwsIcon icon={CONTROL_ICONS.mrap} size={24} />,
          title: m.Name,
          subtitle: (
            <>
              <code>{m.Alias}</code> ·{" "}
              {(m.Regions ?? []).map((r, i) => (
                <span key={r.Bucket}>
                  {i > 0 && ", "}
                  <Link href={bucketHref(r.Bucket!)}>{r.Bucket}</Link> ({r.Region})
                </span>
              ))}
            </>
          ),
          meta: (
            <>
              <Status tone={m.Status === "READY" ? "good" : /FAILED/.test(m.Status ?? "") ? "bad" : "warn"}>{m.Status ?? ""}</Status>
              <span>{ago(m.CreatedAt)}</span>
            </>
          ),
          actions: <ActionForm action={deleteMrap.bind(null, m.Name!)} submit={`Delete ${m.Name}`} icon={<Trash2 size={15} aria-hidden />} tone="danger" confirm={`Delete Multi-Region Access Point ${m.Name}?`} />,
        }))}
      />
    ),
  };
}

// --- Batch Operations ----------------------------------------------------------------

const JOB_TONE = (s?: string) => (s === "Complete" ? "good" : s === "Failed" || s === "Cancelled" ? "bad" : s === "Suspended" ? "warn" : "info");
const ACTIVE = /^(New|Preparing|Ready|Active|Pausing|Cancelling|Completing|Failing)$/;

function operationName(op?: JobOperation) {
  if (!op) return "";
  const key = Object.keys(op).find((k) => (op as Record<string, unknown>)[k]);
  return (key ?? "").replace(/^S3/, "").replace(/([a-z])([A-Z])/g, "$1 $2");
}

async function jobs(): Promise<View> {
  const [list, buckets, roles] = await Promise.all([
    load(async () => {
      const AccountId = await account();
      const client = await control();
      return all(
        (NextToken) => client.send(new ListJobsCommand({ AccountId, NextToken })),
        (r) => r.Jobs,
        (r) => r.NextToken,
      );
    }),
    load(bucketsOf),
    roleOptions(BATCH_ROLE.service as string),
  ]);
  const names = buckets.ok ? buckets.value : [];
  const actions = (
    <Sheet title="Create job" label="Create job" testId="create-job">
      <JobForm buckets={names} roles={roles} roleName={BATCH_ROLE.name} />
    </Sheet>
  );
  const active = list.ok && list.value.some((j) => ACTIVE.test(j.Status ?? ""));
  return {
    actions,
    body: !list.ok ? (
      <ErrorNotice error={list.error} />
    ) : (
      <>
        <LiveRefresh when={active} />
        <List
          label="Jobs"
          empty={<Empty icon={CONTROL_ICONS.batch} />}
          rows={list.value
            .sort((a, b) => (b.CreationTime?.getTime() ?? 0) - (a.CreationTime?.getTime() ?? 0))
            .map((j) => ({
              key: j.JobId!,
              icon: <AwsIcon icon={CONTROL_ICONS.batch} size={24} />,
              title: j.Description || j.JobId,
              subtitle: `${j.Operation ?? ""} · ${j.JobId}`,
              href: controlHref("batch", { id: j.JobId }),
              meta: (
                <>
                  {j.ProgressSummary?.TotalNumberOfTasks != null && (
                    <span>
                      {j.ProgressSummary.NumberOfTasksSucceeded ?? 0}/{j.ProgressSummary.TotalNumberOfTasks}
                    </span>
                  )}
                  {!!j.ProgressSummary?.NumberOfTasksFailed && <Pill tone="bad">{j.ProgressSummary.NumberOfTasksFailed} failed</Pill>}
                  <Pill>P{j.Priority}</Pill>
                  <Status tone={JOB_TONE(j.Status)}>{j.Status ?? ""}</Status>
                  <span>{ago(j.CreationTime)}</span>
                </>
              ),
            }))}
        />
      </>
    ),
  };
}

async function jobDetail(id: string): Promise<View> {
  const job = await load(async () => (await (await control()).send(new DescribeJobCommand({ AccountId: await account(), JobId: id }))).Job!);
  if (!job.ok) return { title: id, body: <ErrorNotice error={job.error} /> };
  const j = job.value;
  const p = j.ProgressSummary;
  const report = j.Report?.Enabled && j.Report.Bucket ? j.Report.Bucket.replace(/^arn:aws:s3:::/, "") : undefined;
  const source = j.ManifestGenerator?.S3JobManifestGenerator?.SourceBucket?.replace(/^arn:aws:s3:::/, "");
  return {
    title: j.Description || id,
    actions: (
      <>
        {j.Status === "Suspended" && <ActionForm action={setJobStatus.bind(null, id, "Ready")} submit="Run job" icon={<Check size={16} aria-hidden />} testId="confirm-job" />}
        {ACTIVE.test(j.Status ?? "") || j.Status === "Suspended" ? (
          <ActionForm action={setJobStatus.bind(null, id, "Cancelled")} submit="Cancel job" icon={<X size={16} aria-hidden />} tone="danger" confirm="Cancel this job?" testId="cancel-job" />
        ) : null}
      </>
    ),
    body: (
      <>
        <LiveRefresh when={ACTIVE.test(j.Status ?? "")} />
        <p>
          <Link href={controlHref("batch")}>Batch Operations</Link>
        </p>
        <Metrics>
          <Metric label="Status" value={<Status tone={JOB_TONE(j.Status)}>{j.Status ?? ""}</Status>} />
          <Metric label="Tasks" value={p?.TotalNumberOfTasks ?? 0} />
          <Metric label="Succeeded" value={p?.NumberOfTasksSucceeded ?? 0} tone="good" />
          <Metric label="Failed" value={p?.NumberOfTasksFailed ?? 0} tone={p?.NumberOfTasksFailed ? "bad" : undefined} />
        </Metrics>
        {j.FailureReasons?.length ? <ErrorNotice error={j.FailureReasons.map((f) => `${f.FailureCode}: ${f.FailureReason}`).join("; ")} /> : null}
        <Section
          title="Configuration"
          actions={
            ACTIVE.test(j.Status ?? "") || j.Status === "Suspended" ? (
              <ActionForm action={setJobPriority.bind(null, id)} submit="Set priority" inline testId="job-priority">
                <input name="priority" type="number" min={0} defaultValue={j.Priority} aria-label="Priority" />
              </ActionForm>
            ) : undefined
          }
        >
          <Facts
            items={[
              ["Job ID", <code>{j.JobId}</code>],
              ["Operation", operationName(j.Operation)],
              ["Priority", j.Priority],
              source && ["Source bucket", <Link href={bucketHref(source)}>{source}</Link>],
              j.Manifest?.Location?.ObjectArn && ["Manifest", <code>{j.Manifest.Location.ObjectArn}</code>],
              j.RoleArn && ["IAM role", <Link href={links.role(j.RoleArn)}>{shortName(j.RoleArn)}</Link>],
              report && ["Completion report", <Link href={bucketHref(report, { prefix: j.Report?.Prefix ? `${j.Report.Prefix}/` : undefined })}>{`s3://${report}/${j.Report?.Prefix ?? ""}`}</Link>],
              j.StatusUpdateReason && ["Status reason", j.StatusUpdateReason],
              ["Created", ago(j.CreationTime)],
              j.TerminationDate && ["Finished", ago(j.TerminationDate)],
            ]}
          />
        </Section>
        <details>
          <summary>Operation</summary>
          <CodeBlock value={JSON.stringify(j.Operation)} label="Job operation" />
        </details>
      </>
    ),
  };
}

// --- Access Grants ------------------------------------------------------------------

async function grants(): Promise<View> {
  const data = await load(async () => {
    const AccountId = await account();
    const client = await control();
    const instance = await optional(() => client.send(new GetAccessGrantsInstanceCommand({ AccountId })));
    if (!instance) return { instance: null, locations: [], grants: [] };
    const [locations, list] = await Promise.all([
      all(
        (NextToken) => client.send(new ListAccessGrantsLocationsCommand({ AccountId, NextToken })),
        (r) => r.AccessGrantsLocationsList,
        (r) => r.NextToken,
      ),
      all(
        (NextToken) => client.send(new ListAccessGrantsCommand({ AccountId, NextToken })),
        (r) => r.AccessGrantsList,
        (r) => r.NextToken,
      ),
    ]);
    return { instance, locations, grants: list };
  });
  if (!data.ok) return { body: <ErrorNotice error={data.error} /> };
  const { instance, locations, grants: list } = data.value;
  if (!instance) {
    return {
      body: <Empty icon="service/AmazonSimpleStorageService" action={<ActionForm action={createGrantsInstance} submit="Create Access Grants instance" testId="create-grants-instance" />} />,
    };
  }
  const roles = await roleOptions(GRANTS_ROLE.service as string);
  const scopeOf = Object.fromEntries(locations.map((l) => [l.AccessGrantsLocationId!, l.LocationScope!]));
  return {
    actions: (
      <>
        <Sheet title="Register location" label="Register location" icon={<Plus size={15} aria-hidden />} testId="create-grants-location">
          <ActionForm action={createGrantsLocation} submit="Register" testId="create-grants-location">
            <Field label="Location" rule={{ ...CreateAccessGrantsLocation.LocationScope, format: "s3url" }} hint="s3:// for the whole account, or s3://bucket/prefix*">
              <input name="scope" required defaultValue="s3://" />
            </Field>
            <AutoPick name="role" label="IAM role" creates={GRANTS_ROLE.name} options={roles} testId="grants-role" />
          </ActionForm>
        </Sheet>
        {locations.length > 0 && (
          <Sheet title="Create grant" label="Create grant" testId="create-grant">
            <ActionForm action={createGrant} submit="Create" testId="create-grant">
              <Field label="Location">
                <select name="location" required>
                  {locations.map((l) => (
                    <option key={l.AccessGrantsLocationId} value={l.AccessGrantsLocationId}>
                      {l.LocationScope}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Subprefix" hint="Optional, like bucket/team/*">
                <input name="subprefix" />
              </Field>
              <Field label="Grantee (IAM user or role ARN)" format="arn">
                <input name="grantee" required />
              </Field>
              <Field label="Permission">
                <select name="permission" defaultValue="READ">
                  <option value="READ">Read</option>
                  <option value="WRITE">Write</option>
                  <option value="READWRITE">Read and write</option>
                </select>
              </Field>
            </ActionForm>
          </Sheet>
        )}
        <ActionForm action={deleteGrantsInstance} submit="Delete Access Grants instance" icon={<Trash2 size={16} aria-hidden />} tone="danger" confirm="Delete this account's Access Grants instance? Its locations and grants must be deleted first." />
      </>
    ),
    body: (
      <>
        <Section title="Instance">
          <Facts items={[["ARN", <code>{instance.AccessGrantsInstanceArn}</code>], instance.IdentityCenterArn && ["Identity Center", <code>{instance.IdentityCenterArn}</code>], ["Created", ago(instance.CreatedAt)]]} />
        </Section>
        <Section title="Locations" count={locations.length} plain>
          <List
            label="Locations"
            empty={<span className="muted">None</span>}
            rows={locations.map((l) => ({
              key: l.AccessGrantsLocationId!,
              title: l.LocationScope,
              subtitle: (
                <>
                  {l.AccessGrantsLocationId} · <Link href={links.role(l.IAMRoleArn!)}>{shortName(l.IAMRoleArn)}</Link>
                </>
              ),
              meta: <span>{ago(l.CreatedAt)}</span>,
              actions: <ActionForm action={deleteGrantsLocation.bind(null, l.AccessGrantsLocationId!)} submit={`Delete location ${l.LocationScope}`} icon={<Trash2 size={15} aria-hidden />} tone="danger" confirm="Delete this location?" />,
            }))}
          />
        </Section>
        <Section title="Grants" count={list.length} plain>
          <List
            label="Grants"
            empty={<span className="muted">None</span>}
            rows={list.map((g) => ({
              key: g.AccessGrantId!,
              title: g.GrantScope ?? scopeOf[g.AccessGrantsLocationId!],
              subtitle: `${g.Grantee?.GranteeType}: ${g.Grantee?.GranteeIdentifier}`,
              meta: (
                <>
                  <Pill tone={g.Permission === "READ" ? "neutral" : "warn"}>{g.Permission}</Pill>
                  <span>{ago(g.CreatedAt)}</span>
                </>
              ),
              actions: <ActionForm action={deleteGrant.bind(null, g.AccessGrantId!)} submit={`Delete grant ${g.AccessGrantId}`} icon={<Trash2 size={15} aria-hidden />} tone="danger" confirm="Delete this grant?" />,
            }))}
          />
        </Section>
      </>
    ),
  };
}

// --- Storage Lens ----------------------------------------------------------------------

const LENS_ID: Rule = { ...PutStorageLensConfiguration.ConfigId, hint: "Letters, digits, - _ .", generate: "name" };

async function lenses(): Promise<View> {
  const data = await load(async () => {
    const AccountId = await account();
    const client = await control();
    const [configs, groups] = await Promise.all([
      all(
        (NextToken) => client.send(new ListStorageLensConfigurationsCommand({ AccountId, NextToken })),
        (r) => r.StorageLensConfigurationList,
        (r) => r.NextToken,
      ),
      all(
        (NextToken) => client.send(new ListStorageLensGroupsCommand({ AccountId, NextToken })),
        (r) => r.StorageLensGroupList,
        (r) => r.NextToken,
      ),
    ]);
    return { configs, groups };
  });
  if (!data.ok) return { body: <ErrorNotice error={data.error} /> };
  const { configs, groups } = data.value;
  return {
    actions: (
      <Sheet title="Create dashboard" label="Create Storage Lens dashboard" testId="create-lens">
        <ActionForm action={createLens} submit="Create" testId="create-lens">
          <Field label="Dashboard name" rule={LENS_ID} taken={configs.map((c) => c.Id!)} unique>
            <input name="id" required autoFocus />
          </Field>
          <label className="check">
            <input type="checkbox" name="activity" /> Activity metrics (advanced)
          </label>
        </ActionForm>
      </Sheet>
    ),
    body: (
      <>
        <Section title="Dashboards" count={configs.length} plain>
          <List
            label="Dashboards"
            empty={<Empty icon={CONTROL_ICONS.lens} />}
            rows={configs.map((c) => ({
              key: c.Id!,
              icon: <AwsIcon icon={CONTROL_ICONS.lens} size={24} />,
              title: c.Id,
              subtitle: c.HomeRegion,
              href: controlHref("storage-lens", { id: c.Id }),
              meta: <Status tone={c.IsEnabled ? "good" : "neutral"}>{c.IsEnabled ? "Enabled" : "Disabled"}</Status>,
            }))}
          />
        </Section>
        {groups.length > 0 && (
          <Section title="Storage Lens groups" count={groups.length} plain>
            <List
              label="Storage Lens groups"
              rows={groups.map((g) => ({
                key: g.Name!,
                title: g.Name,
                subtitle: g.HomeRegion,
                actions: <ActionForm action={deleteLensGroup.bind(null, g.Name!)} submit={`Delete ${g.Name}`} icon={<Trash2 size={15} aria-hidden />} tone="danger" confirm={`Delete Storage Lens group ${g.Name}?`} />,
              }))}
            />
          </Section>
        )}
      </>
    ),
  };
}

async function lensDetail(id: string): Promise<View> {
  const config = await load(async () => (await (await control()).send(new GetStorageLensConfigurationCommand({ AccountId: await account(), ConfigId: id }))).StorageLensConfiguration!);
  if (!config.ok) return { title: id, body: <ErrorNotice error={config.error} /> };
  const c = config.value;
  const def = id === "default-account-dashboard";
  return {
    title: id,
    actions: def ? undefined : <ActionForm action={deleteLens.bind(null, id)} submit="Delete dashboard" icon={<Trash2 size={16} aria-hidden />} tone="danger" confirm={`Delete dashboard ${id}?`} testId="delete-lens" />,
    body: (
      <>
        <p>
          <Link href={controlHref("storage-lens")}>Storage Lens</Link>
        </p>
        <Section title="Dashboard">
          <Facts
            items={[
              ["Status", <Status tone={c.IsEnabled ? "good" : "neutral"}>{c.IsEnabled ? "Enabled" : "Disabled"}</Status>],
              c.StorageLensArn && ["ARN", <code>{c.StorageLensArn}</code>],
              ["Activity metrics", c.AccountLevel?.ActivityMetrics?.IsEnabled ? "On" : "Off"],
              c.Include?.Buckets?.length ? ["Buckets", c.Include.Buckets.join(", ")] : null,
              c.Include?.Regions?.length ? ["Regions", c.Include.Regions.join(", ")] : null,
              c.DataExport?.S3BucketDestination && ["Metrics export", <code>{c.DataExport.S3BucketDestination.Arn}</code>],
            ]}
          />
        </Section>
        <details>
          <summary>Configuration</summary>
          <CodeBlock value={JSON.stringify(c)} label="Storage Lens configuration" />
        </details>
      </>
    ),
  };
}

import type { FunctionConfiguration, FunctionEventInvokeConfig, FunctionUrlConfig, ProvisionedConcurrencyConfigListItem } from "@aws-sdk/client-lambda";
import { ago, bytes } from "@mws-dashboard/aws";
import { ActionForm, CopyButton, Facts, Field, List, Pill, Section, Sheet, Status, Tags } from "@mws-dashboard/ui";
import { Gauge, Globe, Plus, Settings2, Tag, Trash2, Undo2 } from "lucide-react";
import Link from "next/link";

import {
  addProvisioned,
  createUrl,
  deleteAsync,
  deleteProvisioned,
  deleteUrl,
  saveAsync,
  saveConcurrency,
  saveConfiguration,
  saveTags,
  updateUrl,
} from "../../routes/lambda/actions";
import { RUNTIMES } from "../clients";
import { arnHref, arnName } from "../links";
import { DESCRIPTION, DESTINATION, DLQ_TARGET, ENVIRONMENT, EPHEMERAL, EVENT_AGE, HANDLER, LAYER_ARNS, MEMORY, PROVISIONED, RESERVED, RETRIES, ROLE, TIMEOUT } from "../rules";

const linked = (arn: string | undefined) => {
  if (!arn) return null;
  const href = arnHref(arn);
  return href ? <Link href={href}>{arnName(arn)}</Link> : <code>{arn}</code>;
};

function UrlFields({ url }: { url?: FunctionUrlConfig }) {
  return (
    <>
      <div className="form-row">
        <Field label="Auth type">
          <select name="auth" defaultValue={url?.AuthType ?? "NONE"}>
            <option value="NONE">NONE (public, adds the policy statements)</option>
            <option value="AWS_IAM">AWS_IAM</option>
          </select>
        </Field>
        <Field label="Invoke mode">
          <select name="mode" defaultValue={url?.InvokeMode ?? "BUFFERED"}>
            <option>BUFFERED</option>
            <option>RESPONSE_STREAM</option>
          </select>
        </Field>
      </div>
      <Field label="CORS allowed origins" format="list" member="Cors.AllowOrigins">
        <input name="origins" placeholder="https://example.com, *" defaultValue={url?.Cors?.AllowOrigins?.join(", ")} spellCheck={false} />
      </Field>
      <div className="form-row">
        <Field label="Allowed methods">
          <input name="methods" placeholder="*" defaultValue={url?.Cors?.AllowMethods?.join(", ")} spellCheck={false} />
        </Field>
        <Field label="Allowed headers">
          <input name="headers" defaultValue={url?.Cors?.AllowHeaders?.join(", ")} spellCheck={false} />
        </Field>
      </div>
      <label className="check">
        <input type="checkbox" name="credentials" defaultChecked={url?.Cors?.AllowCredentials} /> Allow credentials
      </label>
    </>
  );
}

export function Configuration({
  name,
  c,
  account,
  roles,
  url,
  mwsUrl,
  reserved,
  provisioned,
  asyncConfig,
  tags,
  qualifiers,
  destinations,
}: {
  name: string;
  c: FunctionConfiguration;
  account?: string;
  roles: string[];
  url?: FunctionUrlConfig;
  mwsUrl?: string;
  reserved?: number;
  provisioned: ProvisionedConcurrencyConfigListItem[];
  asyncConfig?: FunctionEventInvokeConfig;
  tags: Record<string, string>;
  qualifiers: string[];
  destinations: string[];
}) {
  const env = c.Environment?.Variables ?? {};
  const logGroup = c.LoggingConfig?.LogGroup ?? `/aws/lambda/${c.FunctionName}`;
  const dlq = c.DeadLetterConfig?.TargetArn || undefined;
  return (
    <>
      <Section
        title="General configuration"
        actions={
          <Sheet title="Configuration" label="Edit configuration" icon={<Settings2 size={16} />} testId="edit-config">
            <ActionForm action={saveConfiguration.bind(null, name)} submit="Save" testId="edit-config">
              <Field label="Description" rule={DESCRIPTION}>
                <input name="description" defaultValue={c.Description} />
              </Field>
              <div className="form-row">
                <Field label="Memory (MB)" rule={MEMORY}>
                  <input name="memory" type="number" min={128} step={1} defaultValue={c.MemorySize} />
                </Field>
                <Field label="Timeout (s)" rule={TIMEOUT}>
                  <input name="timeout" type="number" min={1} defaultValue={c.Timeout} />
                </Field>
                <Field label="Ephemeral storage (MB)" rule={EPHEMERAL}>
                  <input name="ephemeral" inputMode="numeric" defaultValue={c.EphemeralStorage?.Size} />
                </Field>
              </div>
              {c.PackageType !== "Image" && (
                <div className="form-row">
                  <Field label="Runtime">
                    <select name="runtime" defaultValue={c.Runtime}>
                      {[...new Set([c.Runtime!, ...RUNTIMES])].map((r) => (
                        <option key={r}>{r}</option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Handler" rule={HANDLER}>
                    <input name="handler" defaultValue={c.Handler} spellCheck={false} />
                  </Field>
                </div>
              )}
              <Field label="Execution role" rule={ROLE} arn={`arn:aws:iam::${account}:role/{}`} known={roles}>
                <input name="role" defaultValue={c.Role} spellCheck={false} />
              </Field>
              <Field label="Dead-letter queue or topic" rule={{ ...DLQ_TARGET, required: false }} known={destinations.filter((d) => /:(sqs|sns):/.test(d))}>
                <input name="dlq" defaultValue={dlq} spellCheck={false} />
              </Field>
              {dlq && <input type="hidden" name="hadDlq" value="1" />}
              {c.PackageType !== "Image" && (
                <Field label="Layers" rule={{ ...LAYER_ARNS, required: false }}>
                  <textarea name="layers" rows={2} spellCheck={false} defaultValue={c.Layers?.map((l) => l.Arn).join("\n")} />
                </Field>
              )}
              <label className="check">
                <input type="checkbox" name="tracing" value="Active" defaultChecked={c.TracingConfig?.Mode === "Active"} /> Active tracing
              </label>
              <Field label="Environment variables" rule={ENVIRONMENT}>
                <textarea name="env" rows={6} placeholder="KEY=value" spellCheck={false} defaultValue={Object.entries(env).map(([k, v]) => `${k}=${v}`).join("\n")} />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        <Facts
          items={[
            c.Description && ["Description", c.Description],
            c.Handler && ["Handler", <code key="h">{c.Handler}</code>],
            ["Memory", `${c.MemorySize} MB`],
            ["Timeout", `${c.Timeout} s`],
            ["Architecture", c.Architectures?.join(", ")],
            ["Code size", bytes(c.CodeSize)],
            c.EphemeralStorage?.Size && c.EphemeralStorage.Size !== 512 && ["Ephemeral storage", `${c.EphemeralStorage.Size} MB`],
            c.TracingConfig?.Mode === "Active" && ["Tracing", "Active"],
            c.Layers?.length && [
              "Layers",
              c.Layers.map((l) => (
                <div key={l.Arn}>
                  {linked(l.Arn)}:{l.Arn?.split(":").pop()}
                </div>
              )),
            ],
            c.VpcConfig?.VpcId && ["VPC", <Link key="v" href={`/vpc/${encodeURIComponent(c.VpcConfig.VpcId)}`}>{c.VpcConfig.VpcId}</Link>],
            dlq && ["Dead-letter", linked(dlq)],
            c.LastUpdateStatus && c.LastUpdateStatus !== "Successful" && [
              "Last update",
              <Status key="u" tone={c.LastUpdateStatus === "Failed" ? "bad" : "info"}>{c.LastUpdateStatus === "InProgress" ? "Updating" : (c.LastUpdateStatusReason ?? c.LastUpdateStatus)}</Status>,
            ],
            ["Log group", <Link key="l" href={`/logs/group?name=${encodeURIComponent(logGroup)}`}>{logGroup}</Link>],
          ]}
        />
      </Section>
      <Section title="Environment variables" count={Object.keys(env).length}>
        {Object.keys(env).length ? <Facts items={Object.entries(env).map(([k, v]) => [<code key={k}>{k}</code>, <code key={`${k}=`}>{v}</code>])} /> : <span className="muted">—</span>}
      </Section>
      <Section
        title="Function URL"
        icon={<Globe size={16} aria-hidden />}
        actions={
          url ? (
            <>
              <Sheet title="Function URL" label="Edit function URL" icon={<Settings2 size={15} />} testId="edit-url">
                <ActionForm action={updateUrl.bind(null, name)} submit="Save" testId="edit-url">
                  <UrlFields url={url} />
                </ActionForm>
              </Sheet>
              <ActionForm action={deleteUrl.bind(null, name)} submit="Delete function URL" icon={<Trash2 size={15} />} tone="danger" confirm="Delete the function URL?" />
            </>
          ) : (
            <Sheet title="Create function URL" label="Create function URL" icon={<Plus size={16} />} testId="create-url">
              <ActionForm action={createUrl.bind(null, name)} submit="Create" testId="create-url">
                <UrlFields />
              </ActionForm>
            </Sheet>
          )
        }
      >
        {url ? (
          <Facts
            items={[
              [
                "URL",
                <span key="u" className="chips">
                  <code>{url.FunctionUrl}</code>
                  <CopyButton value={url.FunctionUrl!} label="Copy function URL" />
                </span>,
              ],
              mwsUrl && [
                "On MWS",
                <span key="m" className="chips">
                  <a href={mwsUrl} target="_blank" rel="noreferrer" data-testid="function-url">
                    {mwsUrl}
                  </a>
                  <CopyButton value={mwsUrl} label="Copy MWS URL" />
                </span>,
              ],
              ["Auth type", url.AuthType === "NONE" ? <Pill key="a" tone="warn">NONE</Pill> : url.AuthType],
              ["Invoke mode", url.InvokeMode ?? "BUFFERED"],
              url.Cors?.AllowOrigins?.length && ["CORS origins", url.Cors.AllowOrigins.join(", ")],
              ["Created", ago(url.CreationTime)],
            ]}
          />
        ) : (
          <span className="muted">—</span>
        )}
      </Section>
      <Section
        title="Concurrency"
        icon={<Gauge size={16} aria-hidden />}
        actions={
          <>
            <Sheet title="Reserved concurrency" label="Edit reserved concurrency" icon={<Settings2 size={15} />} testId="edit-concurrency">
              <ActionForm action={saveConcurrency.bind(null, name)} submit="Save" testId="edit-concurrency">
                <Field label="Reserved concurrency" rule={RESERVED} hint="Empty: use unreserved account concurrency">
                  <input name="reserved" inputMode="numeric" defaultValue={reserved} />
                </Field>
              </ActionForm>
            </Sheet>
            {qualifiers.length > 0 && (
              <Sheet title="Provisioned concurrency" label="Add provisioned concurrency" icon={<Plus size={16} />} testId="add-provisioned">
                <ActionForm action={addProvisioned.bind(null, name)} submit="Save" testId="add-provisioned">
                  <div className="form-row">
                    <Field label="Version or alias">
                      <select name="qualifier" required>
                        {qualifiers.map((q) => (
                          <option key={q}>{q}</option>
                        ))}
                      </select>
                    </Field>
                    <Field label="Concurrency" rule={PROVISIONED}>
                      <input name="count" inputMode="numeric" required />
                    </Field>
                  </div>
                </ActionForm>
              </Sheet>
            )}
          </>
        }
      >
        <Facts items={[["Reserved", reserved === undefined ? "Unreserved" : reserved === 0 ? <Pill key="t" tone="bad">0 (throttled)</Pill> : reserved]]} />
        {provisioned.length > 0 && (
          <List
            label="Provisioned concurrency"
            rows={provisioned.map((p) => {
              const qualifier = p.FunctionArn?.split(":").pop() ?? "";
              return {
                key: qualifier,
                icon: <Gauge size={18} aria-hidden />,
                title: qualifier,
                subtitle: p.StatusReason,
                meta: (
                  <>
                    <span title="Allocated / requested">
                      {p.AllocatedProvisionedConcurrentExecutions ?? 0} / {p.RequestedProvisionedConcurrentExecutions}
                    </span>
                    <Status tone={p.Status === "READY" ? "good" : p.Status === "FAILED" ? "bad" : "info"}>{p.Status === "IN_PROGRESS" ? "In progress" : (p.Status ?? "")}</Status>
                  </>
                ),
                actions: <ActionForm action={deleteProvisioned.bind(null, name, qualifier)} submit={`Remove provisioned concurrency on ${qualifier}`} icon={<Trash2 size={15} />} tone="danger" />,
              };
            })}
          />
        )}
      </Section>
      <Section
        title="Asynchronous invocation"
        actions={
          <>
            <Sheet title="Asynchronous invocation" label="Edit asynchronous invocation" icon={<Settings2 size={15} />} testId="edit-async">
              <ActionForm action={saveAsync.bind(null, name)} submit="Save" testId="edit-async">
                <div className="form-row">
                  <Field label="Maximum age of event (s)" rule={EVENT_AGE}>
                    <input name="age" inputMode="numeric" defaultValue={asyncConfig?.MaximumEventAgeInSeconds ?? 21600} />
                  </Field>
                  <Field label="Retry attempts" rule={RETRIES}>
                    <input name="retries" inputMode="numeric" defaultValue={asyncConfig?.MaximumRetryAttempts ?? 2} />
                  </Field>
                </div>
                <Field label="On success" rule={DESTINATION} known={destinations}>
                  <input name="onSuccess" defaultValue={asyncConfig?.DestinationConfig?.OnSuccess?.Destination} spellCheck={false} />
                </Field>
                <Field label="On failure" rule={DESTINATION} known={destinations}>
                  <input name="onFailure" defaultValue={asyncConfig?.DestinationConfig?.OnFailure?.Destination} spellCheck={false} />
                </Field>
              </ActionForm>
            </Sheet>
            {asyncConfig && <ActionForm action={deleteAsync.bind(null, name)} submit="Reset asynchronous invocation" icon={<Undo2 size={15} />} confirm="Reset to the defaults?" />}
          </>
        }
      >
        <Facts
          items={[
            ["Maximum age", `${asyncConfig?.MaximumEventAgeInSeconds ?? 21600} s`],
            ["Retry attempts", asyncConfig?.MaximumRetryAttempts ?? 2],
            asyncConfig?.DestinationConfig?.OnSuccess?.Destination && ["On success", linked(asyncConfig.DestinationConfig.OnSuccess.Destination)],
            asyncConfig?.DestinationConfig?.OnFailure?.Destination && ["On failure", linked(asyncConfig.DestinationConfig.OnFailure.Destination)],
          ]}
        />
      </Section>
      <Section
        title="Tags"
        icon={<Tag size={16} aria-hidden />}
        count={Object.keys(tags).length}
        actions={
          <Sheet title="Tags" label="Edit tags" icon={<Settings2 size={15} />} testId="edit-tags">
            <ActionForm action={saveTags.bind(null, name, c.FunctionArn!, Object.keys(tags))} submit="Save" testId="edit-tags">
              <Field label="One Key=Value per line" format="tags">
                <textarea name="tags" rows={6} spellCheck={false} defaultValue={Object.entries(tags).map(([k, v]) => `${k}=${v}`).join("\n")} />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {Object.keys(tags).length ? <Tags tags={tags} /> : <span className="muted">—</span>}
      </Section>
    </>
  );
}

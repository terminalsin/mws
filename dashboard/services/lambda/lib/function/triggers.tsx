import type { EventSourceMappingConfiguration } from "@aws-sdk/client-lambda";
import { ago } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, Field, List, Pill, Section, SERVICES, Sheet, Status } from "@mws-dashboard/ui";
import { Pause, Play, Settings2, Trash2 } from "lucide-react";
import Link from "next/link";

import { createMapping, deleteMapping, setMapping, updateMapping } from "../../routes/lambda/actions";
import { ICONS } from "../clients";
import { pushTriggers, type Statement } from "../lambda";
import { arnHref, arnName } from "../links";
import { ESM } from "../rules";
import { TriggerFields } from "../trigger";

/** The service an ARN or principal belongs to, for its icon. */
export function serviceIcon(svc: string) {
  const id = svc === "logs" ? "cloudwatch" : svc;
  return SERVICES.find((s) => s.id === id || s.endpoints.includes(svc))?.icon ?? ICONS.lambda;
}

const TRANSITIONAL = new Set(["Creating", "Enabling", "Disabling", "Updating", "Deleting"]);

export function Triggers({
  name,
  arn,
  mappings,
  statements,
  sources,
}: {
  name: string;
  arn: string;
  mappings: EventSourceMappingConfiguration[];
  statements: Statement[];
  sources: string[];
}) {
  const [, partition, , region, account] = arn.split(":");
  const push = pushTriggers(statements);
  const used = new Set(mappings.map((m) => m.EventSourceArn));
  return (
    <Section
      title="Triggers"
      count={mappings.length + push.length}
      plain
      actions={
        <Sheet title="Add trigger" label="Add trigger" testId="add-trigger">
          <ActionForm action={createMapping.bind(null, name)} submit="Add" testId="add-trigger">
            <TriggerFields sources={sources.filter((s) => !used.has(s))} rules={ESM} arn={`arn:${partition}:sqs:${region}:${account}:{}`} />
          </ActionForm>
        </Sheet>
      }
    >
      <List
        label="Triggers"
        empty={<Empty icon={ICONS.fn} />}
        rows={[
          ...mappings.map((m) => {
            const enabled = m.State === "Enabled" || m.State === "Enabling";
            const svc = m.EventSourceArn?.split(":")[2] ?? "";
            const href = arnHref(m.EventSourceArn);
            const failed = m.LastProcessingResult && !/^(OK|No records processed)$/i.test(m.LastProcessingResult);
            const filter = m.FilterCriteria?.Filters?.[0]?.Pattern;
            return {
              key: m.UUID!,
              icon: <AwsIcon icon={serviceIcon(svc)} size={24} />,
              title: href ? <Link href={href}>{arnName(m.EventSourceArn)}</Link> : arnName(m.EventSourceArn),
              subtitle: (
                <>
                  {failed ? <span className="tone-bad">{m.LastProcessingResult}</span> : m.StateTransitionReason && m.StateTransitionReason !== "USER_INITIATED" ? m.StateTransitionReason : null}
                  {filter && (
                    <details>
                      <summary>filter</summary>
                      <CodeBlock value={filter} />
                    </details>
                  )}
                </>
              ),
              meta: (
                <>
                  {m.FunctionResponseTypes?.includes("ReportBatchItemFailures") && <Pill title="Reports batch item failures">partial</Pill>}
                  {m.MaximumBatchingWindowInSeconds ? <Pill title="Batch window">{m.MaximumBatchingWindowInSeconds}s</Pill> : null}
                  {m.BatchSize && <Pill title="Batch size">×{m.BatchSize}</Pill>}
                  {m.LastModified && <span title="Last modified">{ago(m.LastModified)}</span>}
                  <Status tone={m.State === "Enabled" ? "good" : TRANSITIONAL.has(m.State ?? "") ? "info" : "neutral"}>{m.State ?? ""}</Status>
                </>
              ),
              actions: (
                <>
                  <Sheet title={`Trigger: ${arnName(m.EventSourceArn)}`} label="Edit trigger" icon={<Settings2 size={15} aria-hidden />} testId="edit-trigger">
                    <ActionForm action={updateMapping.bind(null, name, m.UUID!)} submit="Save" testId="edit-trigger">
                      <div className="form-row">
                        <Field label="Batch size" rule={ESM.batch} member="BatchSize">
                          <input name="batch" inputMode="numeric" defaultValue={m.BatchSize} />
                        </Field>
                        <Field label="Batch window (s)" rule={ESM.window} member="MaximumBatchingWindowInSeconds">
                          <input name="window" inputMode="numeric" defaultValue={m.MaximumBatchingWindowInSeconds} />
                        </Field>
                      </div>
                      <Field label="Filter pattern" rule={ESM.filter}>
                        <textarea name="filter" rows={4} spellCheck={false} defaultValue={filter ? JSON.stringify(JSON.parse(filter), null, 2) : ""} />
                      </Field>
                      <label className="check">
                        <input type="checkbox" name="partial" defaultChecked={m.FunctionResponseTypes?.includes("ReportBatchItemFailures")} /> Report batch item failures
                      </label>
                    </ActionForm>
                  </Sheet>
                  <ActionForm action={setMapping.bind(null, name, m.UUID!, !enabled)} submit={enabled ? "Disable trigger" : "Enable trigger"} icon={enabled ? <Pause size={15} /> : <Play size={15} />} />
                  <ActionForm action={deleteMapping.bind(null, name, m.UUID!)} submit="Delete trigger" icon={<Trash2 size={15} />} tone="danger" confirm="Delete this trigger?" />
                </>
              ),
            };
          }),
          ...push.map((t) => {
            const href = arnHref(t.source);
            return {
              key: `push-${t.sid}-${t.service}`,
              icon: <AwsIcon icon={serviceIcon(t.service)} size={24} />,
              title: t.source ? href ? <Link href={href}>{arnName(t.source)}</Link> : arnName(t.source) : `${t.service}.amazonaws.com`,
              subtitle: <code>{t.sid}</code>,
              meta: <Pill title="Allowed by the resource-based policy">policy</Pill>,
            };
          }),
        ]}
      />
    </Section>
  );
}

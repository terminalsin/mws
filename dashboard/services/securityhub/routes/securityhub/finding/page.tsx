import { GetFindingHistoryCommand, GetFindingsCommand, type FindingHistoryRecord } from "@aws-sdk/client-securityhub";
import { ago, all, load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, ErrorNotice, Facts, Field, List, Page, Pill, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { BatchUpdateFindings as Rules } from "@mws-dashboard/ui/model/securityhub";
import { BellOff, CheckCircle2, Clock, ExternalLink, Pencil, RotateCcw, ShieldCheck } from "lucide-react";
import Link from "next/link";
import type { Metadata } from "next";

import { ICONS, SEVERITY_LABELS, WORKFLOWS, securityhub, severity, word, workflowTone } from "../../../lib/clients";
import { productHref, resourceHref } from "../../../lib/links";
import { productIcon } from "../../../lib/presets";
import { setWorkflow, updateFinding } from "../actions";

export const metadata: Metadata = { title: "Finding · Security Hub" };

type Props = { searchParams: Promise<{ id?: string; product?: string }> };

/** What changed in one history record, in a line. */
function change(h: FindingHistoryRecord) {
  const updates = (h.Updates ?? []).map((u) => `${u.UpdatedField}: ${u.OldValue ?? "∅"} → ${u.NewValue ?? "∅"}`);
  if (h.FindingCreated) return "Finding created";
  return updates.join(" · ") || word(h.UpdateSource?.Type);
}

export default async function Finding({ searchParams }: Props) {
  const { id = "", product = "" } = await searchParams;
  const back = { href: "/securityhub", label: "Findings" };
  const data = await load(async () => {
    const client = await securityhub();
    const f = (await client.send(new GetFindingsCommand({ Filters: { Id: [{ Value: id, Comparison: "EQUALS" }], ...(product ? { ProductArn: [{ Value: product, Comparison: "EQUALS" }] } : {}) } }))).Findings?.[0];
    if (!f) throw new Error(`Finding ${id} not found`);
    const history = await all(
      (NextToken) => client.send(new GetFindingHistoryCommand({ FindingIdentifier: { Id: f.Id!, ProductArn: f.ProductArn! }, NextToken })),
      (r) => r.Records,
      (r) => r.NextToken,
    ).catch(() => [] as FindingHistoryRecord[]);
    return { f, history };
  });
  if (!data.ok) {
    return (
      <Page title="Finding" back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { f, history } = data.value;
  const sev = severity(f.Severity?.Label);
  const status = f.Workflow?.Status ?? "NEW";
  const source = productHref(f.Id, f.ProductArn);
  const set = (to: "NEW" | "RESOLVED" | "SUPPRESSED", label: string, icon: React.ReactNode) =>
    status !== to && <ActionForm key={to} action={setWorkflow.bind(null, f.Id!, f.ProductArn!, to)} submit={`${label} finding`} icon={icon} testId={`workflow-${to.toLowerCase()}`} />;
  return (
    <Page
      title={f.Title}
      icon={productIcon(f.ProductArn, f.ProductName)}
      back={back}
      subtitle={f.Id}
      actions={
        <>
          {(status === "RESOLVED" || status === "SUPPRESSED") && set("NEW", "Reopen", <RotateCcw size={16} />)}
          {set("RESOLVED", "Resolve", <CheckCircle2 size={16} />)}
          {set("SUPPRESSED", "Suppress", <BellOff size={16} />)}
          <Sheet title="Update finding" label="Update finding" icon={<Pencil size={16} />} testId="update-finding">
            <ActionForm action={updateFinding.bind(null, f.Id!, f.ProductArn!)} submit="Update" testId="update-finding">
              <div className="form-row">
                <Field label="Workflow status">
                  <select name="workflow" defaultValue={status}>
                    {WORKFLOWS.map((w) => (
                      <option key={w} value={w}>
                        {word(w)}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Severity">
                  <select name="severity" defaultValue={f.Severity?.Label ?? ""}>
                    {SEVERITY_LABELS.map((l) => (
                      <option key={l} value={l}>
                        {severity(l).label}
                      </option>
                    ))}
                  </select>
                </Field>
              </div>
              <Field label="Note" rule={Rules.Note?.fields?.Text}>
                <textarea name="note" rows={3} defaultValue={f.Note?.Text} />
              </Field>
            </ActionForm>
          </Sheet>
        </>
      }
    >
      <Specs
        items={[
          { label: "Severity", icon: <AwsIcon icon={ICONS.securityhub} size={16} />, value: <Status tone={sev.tone}>{sev.label}</Status> },
          { label: "Workflow", icon: <CheckCircle2 size={15} />, value: <Status tone={workflowTone(status)}>{word(status)}</Status> },
          f.Compliance?.Status && { label: "Compliance", icon: <ShieldCheck size={15} />, value: <Pill tone={f.Compliance.Status === "PASSED" ? "good" : f.Compliance.Status === "FAILED" ? "bad" : "neutral"}>{word(f.Compliance.Status)}</Pill> },
          f.RecordState === "ARCHIVED" && { label: "Record state", icon: <Clock size={15} />, value: "Archived" },
          { label: "Updated", icon: <Clock size={15} />, value: <span title={when(f.UpdatedAt)}>{ago(f.UpdatedAt)}</span> },
        ]}
      />
      {f.Description && <p>{f.Description}</p>}
      {f.Note?.Text && (
        <div className="banner">
          {f.Note.Text} <span className="muted">— {f.Note.UpdatedBy}</span>
        </div>
      )}
      <Section title="Resources" count={f.Resources?.length} plain>
        <List
          label="Resources"
          rows={(f.Resources ?? []).map((r, i) => ({
            key: `${r.Id}-${i}`,
            title: r.Id,
            subtitle: [r.Region, r.Partition, Object.entries(r.Tags ?? {}).map(([k, v]) => `${k}=${v}`).join(", ")].filter(Boolean).join(" · "),
            href: resourceHref(r.Id, r.Type),
            meta: <Pill>{r.Type}</Pill>,
          }))}
        />
      </Section>
      <Section title="Details">
        <Facts
          items={[
            [
              "Product",
              source ? (
                <Link key="p" href={source}>
                  {f.ProductName ?? f.ProductArn}
                </Link>
              ) : (
                (f.ProductName ?? f.ProductArn)
              ),
            ],
            f.CompanyName && ["Company", f.CompanyName],
            ["Account", f.AwsAccountId],
            f.Region && ["Region", f.Region],
            ["Generator", <code key="g">{f.GeneratorId}</code>],
            (f.Types ?? []).length > 0 && ["Types", f.Types!.join(", ")],
            f.Confidence !== undefined && ["Confidence", f.Confidence],
            f.Criticality !== undefined && ["Criticality", f.Criticality],
            f.Compliance?.SecurityControlId && ["Control", f.Compliance.SecurityControlId],
            (f.Compliance?.AssociatedStandards ?? []).length > 0 && ["Standards", f.Compliance!.AssociatedStandards!.map((s) => s.StandardsId).join(", ")],
            f.VerificationState && ["Verification", word(f.VerificationState)],
            ["Created", when(f.CreatedAt)],
            f.FirstObservedAt && ["First observed", when(f.FirstObservedAt)],
            f.LastObservedAt && ["Last observed", when(f.LastObservedAt)],
            f.Remediation?.Recommendation?.Text && [
              "Remediation",
              f.Remediation.Recommendation.Url ? (
                <a key="r" href={f.Remediation.Recommendation.Url} target="_blank" rel="noreferrer">
                  {f.Remediation.Recommendation.Text} <ExternalLink size={12} aria-hidden />
                </a>
              ) : (
                f.Remediation.Recommendation.Text
              ),
            ],
            ...Object.entries(f.UserDefinedFields ?? {}).map(([k, v]): [string, string] => [k, v]),
          ]}
        />
      </Section>
      {history.length > 0 && (
        <Section title="History" count={history.length} plain>
          <List
            label="History"
            rows={history.map((h, i) => ({
              key: `${h.UpdateTime?.toISOString()}-${i}`,
              title: change(h),
              subtitle: [word(h.UpdateSource?.Type), h.UpdateSource?.Identity].filter(Boolean).join(" · "),
              meta: <span title={when(h.UpdateTime)}>{ago(h.UpdateTime)}</span>,
            }))}
          />
        </Section>
      )}
      {Object.keys(f.ProductFields ?? {}).length > 0 && (
        <Section title="Product fields">
          <Facts items={Object.entries(f.ProductFields ?? {}).map(([k, v]): [string, string] => [k, v])} />
        </Section>
      )}
      <Section title="JSON">
        <CodeBlock value={JSON.stringify(f, null, 2)} label="Finding JSON" />
      </Section>
    </Page>
  );
}

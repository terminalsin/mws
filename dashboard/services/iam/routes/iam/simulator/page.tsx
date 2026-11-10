import { ListRolesCommand, ListUsersCommand, SimulateCustomPolicyCommand, SimulatePrincipalPolicyCommand, type EvaluationResult } from "@aws-sdk/client-iam";
import { all, load } from "@mws-dashboard/aws";
import { ErrorNotice, Field, Page, Section, Status, Table } from "@mws-dashboard/ui";
import { FlaskConical } from "lucide-react";
import type { Metadata } from "next";

import { iam } from "../../../lib/clients";
import { RULES } from "../../../lib/rules";

export const metadata: Metadata = { title: "Policy simulator" };

type Props = { searchParams: Promise<{ principal?: string; policy?: string; actions?: string; resources?: string }> };

const split = (s: string | undefined) => (s ?? "").split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

const TONE: Record<string, "good" | "bad" | "warn"> = { allowed: "good", explicitDeny: "bad", implicitDeny: "warn" };
const WORD: Record<string, string> = { allowed: "allowed", explicitDeny: "denied by a statement", implicitDeny: "not allowed" };

/** IAM's policy simulator: would this user or role (or this policy) be
 * allowed these actions on these resources, and which statement decides. */
export default async function Simulator({ searchParams }: Props) {
  const { principal = "", policy = "", actions = "", resources = "" } = await searchParams;
  const ran = !!actions && (!!principal || !!policy);
  const [entities, result] = await Promise.all([
    load(async () => {
      const client = await iam();
      const next = (r: { IsTruncated?: boolean; Marker?: string }) => (r.IsTruncated ? r.Marker : undefined);
      const [users, roles] = await Promise.all([
        all((Marker) => client.send(new ListUsersCommand({ Marker })), (r) => r.Users, next),
        all((Marker) => client.send(new ListRolesCommand({ Marker })), (r) => r.Roles, next),
      ]);
      return [...users.map((u) => ({ arn: u.Arn!, label: `${u.UserName} (user)` })), ...roles.map((r) => ({ arn: r.Arn!, label: `${r.RoleName} (role)` }))];
    }),
    ran
      ? load(async () => {
          const client = await iam();
          const ActionNames = split(actions);
          const ResourceArns = split(resources).length ? split(resources) : undefined;
          const results: EvaluationResult[] = [];
          let Marker: string | undefined;
          do {
            const out = principal
              ? await client.send(new SimulatePrincipalPolicyCommand({ PolicySourceArn: principal, ActionNames, ResourceArns, PolicyInputList: policy ? [policy] : undefined, Marker }))
              : await client.send(new SimulateCustomPolicyCommand({ PolicyInputList: [policy], ActionNames, ResourceArns, Marker }));
            results.push(...(out.EvaluationResults ?? []));
            Marker = out.IsTruncated ? out.Marker : undefined;
          } while (Marker);
          return results;
        })
      : null,
  ]);
  return (
    <Page title="Policy simulator" back={{ href: "/iam", label: "IAM" }}>
      <Section>
        <form className="action-form" action="/iam/simulator" data-testid="simulate">
          <Field label="User or role">
            <select name="principal" defaultValue={principal}>
              <option value="">Only the policy below</option>
              {(entities.ok ? entities.value : []).map((e) => (
                <option key={e.arn} value={e.arn}>
                  {e.label}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Actions" hint="Comma separated: s3:GetObject, sqs:SendMessage">
            <input name="actions" required defaultValue={actions} placeholder="s3:GetObject" />
          </Field>
          <Field label="Resources" hint="ARNs, comma separated; empty means *">
            <input name="resources" defaultValue={resources} placeholder="arn:aws:s3:::bucket/key" />
          </Field>
          <Field label="Policy to add (or test alone)" rule={{ ...RULES.document, required: false }}>
            <textarea name="policy" rows={6} defaultValue={policy} aria-label="Policy to simulate" />
          </Field>
          <div className="form-row">
            <button type="submit" className="button primary">
              <FlaskConical size={16} aria-hidden />
              <span>Run simulation</span>
            </button>
          </div>
        </form>
      </Section>
      {result && !result.ok && <ErrorNotice error={result.error} />}
      {result?.ok && (
        <Section title="Results" count={result.value.length} plain>
          <Table
            label="Simulation results"
            rowKey={(r) => `${r.EvalActionName}:${r.EvalResourceName}`}
            rows={result.value}
            columns={[
              { header: "Action", cell: (r) => <code>{r.EvalActionName}</code> },
              { header: "Resource", cell: (r) => <code>{r.EvalResourceName}</code> },
              { header: "Decision", cell: (r) => <Status tone={TONE[r.EvalDecision!] ?? "neutral"}>{WORD[r.EvalDecision!] ?? r.EvalDecision}</Status> },
              {
                header: "Decided by",
                cell: (r) =>
                  (r.MatchedStatements ?? []).map((m) => m.SourcePolicyId).filter(Boolean).join(", ") ||
                  (r.OrganizationsDecisionDetail?.AllowedByOrganizations === false ? "an SCP" : r.PermissionsBoundaryDecisionDetail?.AllowedByPermissionsBoundary === false ? "the permissions boundary" : ""),
              },
              { header: "Missing context", cell: (r) => (r.MissingContextValues ?? []).join(", ") },
            ]}
          />
        </Section>
      )}
    </Page>
  );
}

import { DescribeActiveReceiptRuleSetCommand, DescribeReceiptRuleSetCommand, type ReceiptAction, type ReceiptRule } from "@aws-sdk/client-ses";
import { ListEmailIdentitiesCommand } from "@aws-sdk/client-sesv2";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, List, Page, Pill, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { ArrowDown, ArrowUp, Check, Inbox, Pencil, Plus, Trash2, X } from "lucide-react";
import type { Metadata } from "next";

import { buckets, functions, topics } from "../../../lib/choices";
import { ICONS, ses, sesV1 } from "../../../lib/clients";
import { RuleFields, type RuleDefaults } from "../../../lib/forms";
import { RULE_NAME } from "../../../lib/rules";
import { createRule, deleteRule, deleteRuleSet, moveRule, setActiveRuleSet, updateRule } from "../receipt-actions";

export const metadata: Metadata = { title: "Receipt rule set" };

type Props = { searchParams: Promise<{ name?: string }> };

function describeAction(a: ReceiptAction): { icon: string | null; text: string; href?: string } {
  if (a.S3Action) return { icon: ICONS.s3, text: `S3 ${a.S3Action.BucketName}/${a.S3Action.ObjectKeyPrefix ?? ""}`, href: `/s3/${encodeURIComponent(a.S3Action.BucketName ?? "")}` };
  if (a.SNSAction) return { icon: ICONS.sns, text: `SNS ${a.SNSAction.TopicArn?.split(":").pop()}`, href: `/sns/topic?arn=${encodeURIComponent(a.SNSAction.TopicArn ?? "")}` };
  if (a.LambdaAction) return { icon: ICONS.lambda, text: `Lambda ${a.LambdaAction.FunctionArn?.split(":").pop()} (${a.LambdaAction.InvocationType ?? "Event"})`, href: `/lambda/${a.LambdaAction.FunctionArn?.split(":")[6] ?? ""}` };
  if (a.BounceAction) return { icon: null, text: `Bounce ${a.BounceAction.SmtpReplyCode} ${a.BounceAction.StatusCode ?? ""}` };
  if (a.AddHeaderAction) return { icon: null, text: `Header ${a.AddHeaderAction.HeaderName}: ${a.AddHeaderAction.HeaderValue}` };
  if (a.StopAction) return { icon: null, text: "Stop rule set" };
  if (a.WorkmailAction) return { icon: null, text: "WorkMail (recorded only)" };
  return { icon: null, text: "Connect (recorded only)" };
}

function defaultsOf(r: ReceiptRule): RuleDefaults {
  const find = <K extends keyof ReceiptAction>(k: K) => r.Actions?.find((a) => a[k])?.[k];
  const s3 = find("S3Action");
  const sns = find("SNSAction");
  const lambda = find("LambdaAction");
  const bounce = find("BounceAction");
  const header = find("AddHeaderAction");
  return {
    name: r.Name,
    enabled: !!r.Enabled,
    scan: !!r.ScanEnabled,
    tls: r.TlsPolicy ?? "Optional",
    recipients: r.Recipients ?? [],
    header: header && { name: header.HeaderName ?? "", value: header.HeaderValue ?? "" },
    s3: s3 && { bucket: s3.BucketName ?? "", prefix: s3.ObjectKeyPrefix, topic: s3.TopicArn },
    sns: sns && { topic: sns.TopicArn ?? "", encoding: sns.Encoding },
    lambda: lambda && { fn: lambda.FunctionArn ?? "", invocation: lambda.InvocationType },
    bounce: bounce && { code: bounce.SmtpReplyCode ?? "550", status: bounce.StatusCode, message: bounce.Message ?? "", sender: bounce.Sender ?? "" },
    stop: !!find("StopAction"),
  };
}

export default async function RuleSet({ searchParams }: Props) {
  const { name = "" } = await searchParams;
  const back = { href: "/ses?tab=receiving", label: "Email receiving" };
  const data = await load(async () => {
    const v1 = await sesV1();
    const [set, active, snsTopics, s3, fns, identities] = await Promise.all([
      v1.send(new DescribeReceiptRuleSetCommand({ RuleSetName: name })),
      v1.send(new DescribeActiveReceiptRuleSetCommand({})).then((r) => r.Metadata?.Name),
      topics(),
      buckets(),
      functions(),
      (await ses())
        .send(new ListEmailIdentitiesCommand({ PageSize: 1000 }))
        .then((r) => (r.EmailIdentities ?? []).filter((i) => i.VerificationStatus === "SUCCESS").map((i) => i.IdentityName!))
        .catch(() => []),
    ]);
    return { set, active, snsTopics, s3, fns, identities };
  });
  if (!data.ok) {
    return (
      <Page title={name || "Rule set"} icon={ICONS.email} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { set, active, snsTopics, s3, fns, identities } = data.value;
  const rules = set.Rules ?? [];
  const names = rules.map((r) => r.Name!);
  const isActive = active === name;
  const choices = { topics: snsTopics, buckets: s3, functions: fns, identities };
  return (
    <Page
      title={name}
      icon={ICONS.email}
      back={back}
      subtitle="Receipt rule set"
      actions={
        <>
          {isActive ? (
            <ActionForm action={setActiveRuleSet.bind(null, null)} submit="Deactivate rule set" icon={<X size={16} />} testId="deactivate-rule-set" />
          ) : (
            <ActionForm action={setActiveRuleSet.bind(null, name)} submit="Set as active" icon={<Check size={16} />} testId="activate-rule-set" />
          )}
          <ActionForm action={deleteRuleSet.bind(null, name, true)} submit="Delete rule set" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} testId="delete-rule-set" />
        </>
      }
    >
      <Specs
        items={[
          { label: "Status", icon: <Inbox size={15} />, value: <Status tone={isActive ? "good" : "neutral"}>{isActive ? "active" : "inactive"}</Status> },
          { label: "Created", icon: <Inbox size={15} />, value: ago(set.Metadata?.CreatedTimestamp) },
        ]}
      />
      <Section
        title="Receipt rules"
        count={rules.length}
        plain
        actions={
          <Sheet title="Create rule" label="Create rule" icon={<Plus size={16} />} testId="create-rule">
            <ActionForm action={createRule.bind(null, name)} submit="Create rule" testId="create-rule">
              <RuleFields defaults={{ enabled: true, scan: false, tls: "Optional", recipients: [] }} nameRule={RULE_NAME} others={names} {...choices} />
            </ActionForm>
          </Sheet>
        }
      >
        <List
          label="Receipt rules"
          empty={<Empty icon={ICONS.email} />}
          rows={rules.map((r, n) => {
            const actions = (r.Actions ?? []).map(describeAction);
            const first = actions.find((a) => a.icon);
            return {
              key: r.Name!,
              icon: first?.icon ? <AwsIcon icon={first.icon} size={22} /> : <Inbox size={18} aria-hidden />,
              title: `${n + 1}. ${r.Name}`,
              subtitle: `${r.Recipients?.length ? r.Recipients.join(", ") : "All recipients"} → ${actions.map((a) => a.text).join(" · ") || "no actions"}`,
              meta: (
                <>
                  {r.ScanEnabled && <Pill>scan</Pill>}
                  {r.TlsPolicy === "Require" && <Pill>TLS</Pill>}
                  <Status tone={r.Enabled ? "good" : "neutral"}>{r.Enabled ? "enabled" : "disabled"}</Status>
                </>
              ),
              actions: (
                <>
                  {n > 0 && <ActionForm action={moveRule.bind(null, name, r.Name!, n > 1 ? names[n - 2] : null)} submit={`Move ${r.Name} up`} icon={<ArrowUp size={15} />} />}
                  {n < rules.length - 1 && <ActionForm action={moveRule.bind(null, name, r.Name!, names[n + 1])} submit={`Move ${r.Name} down`} icon={<ArrowDown size={15} />} />}
                  <Sheet title={`Edit ${r.Name}`} label={`Edit ${r.Name}`} icon={<Pencil size={15} />} testId={`edit-rule-${r.Name}`}>
                    <ActionForm action={updateRule.bind(null, name)} submit="Save" testId={`edit-rule-${r.Name}`}>
                      <RuleFields defaults={defaultsOf(r)} nameRule={RULE_NAME} others={names.filter((x) => x !== r.Name)} editing {...choices} />
                    </ActionForm>
                  </Sheet>
                  <ActionForm action={deleteRule.bind(null, name, r.Name!)} submit={`Delete ${r.Name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${r.Name}?`} />
                </>
              ),
            };
          })}
        />
      </Section>
    </Page>
  );
}

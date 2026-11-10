import { DescribeActiveReceiptRuleSetCommand, ListReceiptFiltersCommand, ListReceiptRuleSetsCommand } from "@aws-sdk/client-ses";
import { GetAccountCommand, ListSuppressedDestinationsCommand, type GetAccountCommandOutput } from "@aws-sdk/client-sesv2";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Metric, Metrics, Pill, Section, Sheet, Status } from "@mws-dashboard/ui";
import { PutAccountDetails, PutSuppressedDestination } from "@mws-dashboard/ui/model/sesv2";
import { CreateReceiptFilter as ReceiptFilter } from "@mws-dashboard/ui/model/ses";
import { MoreFields } from "@mws-dashboard/ui/presets";
import { Ban, Check, Eraser, Inbox, Pause, Play, Rocket, ShieldBan, Trash2, X } from "lucide-react";

import { configSets, templates } from "../../lib/choices";
import { configSetHref, ICONS, ruleSetHref, ses, sesV1, templateHref } from "../../lib/clients";
import { htmlText, receivedMail, sesMail } from "../../lib/outbox";
import { CONFIG_SET_NAME, RULE_SET_NAME, TEMPLATE_NAME } from "../../lib/rules";
import { TemplateFields } from "../../lib/templates";
import { clearOutbox, deleteMail, requestProduction, setAccountSending, setAccountSuppression, suppress, unsuppress } from "./actions";
import { createConfigSet, deleteConfigSet } from "./config-actions";
import { createFilter, createRuleSet, deleteFilter, deleteRuleSet, receiveTest, setActiveRuleSet } from "./receipt-actions";
import { createTemplate, deleteTemplate } from "./template-actions";

export function AccountPanel({ account }: { account: GetAccountCommandOutput }) {
  const production = !!account.ProductionAccessEnabled;
  const quota = account.SendQuota;
  return (
    <Section
      title="Account"
      plain
      actions={
        <>
          {!production && (
            <Sheet title="Request production access" label="Request production access" icon={<Rocket size={16} />} testId="request-production">
              <ActionForm action={requestProduction} submit="Submit request" testId="request-production">
                <Field label="Mail type" rule={PutAccountDetails.MailType}>
                  <select name="mailType" defaultValue="TRANSACTIONAL">
                    <option value="TRANSACTIONAL">Transactional</option>
                    <option value="MARKETING">Marketing</option>
                  </select>
                </Field>
                <Field label="Website URL" rule={{ ...PutAccountDetails.WebsiteURL, format: "url" }} member="WebsiteURL">
                  <input name="website" required placeholder="https://example.com" />
                </Field>
                <Field label="Use case" rule={PutAccountDetails.UseCaseDescription} member="UseCaseDescription">
                  <textarea name="useCase" rows={3} />
                </Field>
                <Field label="Contact language" rule={PutAccountDetails.ContactLanguage}>
                  <select name="language" defaultValue="EN">
                    <option value="EN">English</option>
                    <option value="JA">Japanese</option>
                  </select>
                </Field>
              </ActionForm>
            </Sheet>
          )}
          <ActionForm
            action={setAccountSending.bind(null, !account.SendingEnabled)}
            submit={account.SendingEnabled ? "Pause sending for the account" : "Resume sending for the account"}
            icon={account.SendingEnabled ? <Pause size={16} /> : <Play size={16} />}
            confirm={account.SendingEnabled ? "Pause all sending from this account in this Region?" : undefined}
            testId="account-sending"
          />
        </>
      }
    >
      <Metrics>
        <Metric label="Sending" value={production ? "Production" : "Sandbox"} tone={production ? "good" : "warn"} />
        <Metric label="Status" value={account.SendingEnabled ? (account.EnforcementStatus?.toLowerCase() ?? "healthy") : "paused"} tone={account.SendingEnabled ? "good" : "bad"} />
        <Metric label="Sent in 24h" value={quota?.SentLast24Hours ?? 0} />
        <Metric label="Daily quota" value={quota?.Max24HourSend ?? "—"} />
        <Metric label="Max send rate" value={quota?.MaxSendRate !== undefined ? `${quota.MaxSendRate}/s` : "—"} />
      </Metrics>
      {account.Details?.ReviewDetails?.Status && account.Details.ReviewDetails.Status !== "GRANTED" && (
        <div className="banner">Production access review: {account.Details.ReviewDetails.Status.toLowerCase()}</div>
      )}
    </Section>
  );
}

export async function ConfigSets() {
  const sets = await load(configSets);
  const create = (
    <Sheet title="Create configuration set" label="Create configuration set" testId="create-config-set">
      <ActionForm action={createConfigSet} submit="Create" testId="create-config-set">
        <Field label="Name" rule={CONFIG_SET_NAME} taken={sets.ok ? sets.value : undefined} unique member="ConfigurationSetName">
          <input name="name" required autoFocus />
        </Field>
        <label className="check">
          <input type="checkbox" name="sending" defaultChecked /> Sending enabled
        </label>
        <label className="check">
          <input type="checkbox" name="reputation" /> Reputation metrics
        </label>
        <MoreFields label="TLS, tracking domain">
          <Field label="TLS to the receiving server" member="TlsPolicy">
            <select name="tls" defaultValue="OPTIONAL">
              <option value="OPTIONAL">Optional</option>
              <option value="REQUIRE">Require</option>
            </select>
          </Field>
          <Field label="Custom redirect domain (open and click tracking)" rule={{ format: "domain" }} member="CustomRedirectDomain">
            <input name="redirectDomain" placeholder="track.example.com" />
          </Field>
        </MoreFields>
      </ActionForm>
    </Sheet>
  );
  return (
    <Section title="Configuration sets" count={sets.ok ? sets.value.length : undefined} plain actions={create}>
      {sets.ok ? (
        <List
          label="Configuration sets"
          empty={<Empty icon={ICONS.email} action={create} />}
          rows={sets.value.map((name) => ({
            key: name,
            icon: <AwsIcon icon={ICONS.email} size={22} />,
            title: name,
            href: configSetHref(name),
            actions: <ActionForm action={deleteConfigSet.bind(null, name, false)} submit={`Delete ${name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${name}?`} />,
          }))}
        />
      ) : (
        <ErrorNotice error={sets.error} />
      )}
    </Section>
  );
}

export async function Templates() {
  const list = await load(templates);
  const create = (
    <Sheet title="Create template" label="Create template" testId="create-template">
      <ActionForm action={createTemplate} submit="Create" testId="create-template">
        <TemplateFields nameRule={TEMPLATE_NAME} taken={list.ok ? list.value.map((t) => t.TemplateName!) : []} />
      </ActionForm>
    </Sheet>
  );
  return (
    <Section title="Email templates" count={list.ok ? list.value.length : undefined} plain actions={create}>
      {list.ok ? (
        <List
          label="Templates"
          empty={<Empty icon={ICONS.email} action={create} />}
          rows={list.value.map((t) => ({
            key: t.TemplateName!,
            icon: <AwsIcon icon={ICONS.email} size={22} />,
            title: t.TemplateName,
            href: templateHref(t.TemplateName),
            meta: <span>{ago(t.CreatedTimestamp)}</span>,
            actions: (
              <ActionForm action={deleteTemplate.bind(null, t.TemplateName!, false)} submit={`Delete ${t.TemplateName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${t.TemplateName}?`} />
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={list.error} />
      )}
    </Section>
  );
}

export async function Receiving() {
  const data = await load(async () => {
    const v1 = await sesV1();
    const [sets, active, filters, received] = await Promise.all([
      all(
        (NextToken) => v1.send(new ListReceiptRuleSetsCommand({ NextToken })),
        (r) => r.RuleSets,
        (r) => r.NextToken,
      ),
      v1.send(new DescribeActiveReceiptRuleSetCommand({})).then((r) => r.Metadata?.Name),
      v1.send(new ListReceiptFiltersCommand({})).then((r) => r.Filters ?? []),
      receivedMail().catch(() => []),
    ]);
    return { sets, active, filters, received };
  });
  if (!data.ok) return <ErrorNotice error={data.error} />;
  const { sets, active, filters, received } = data.value;
  const names = sets.map((s) => s.Name!);
  return (
    <>
      <Section
        title="Receipt rule sets"
        count={sets.length}
        plain
        actions={
          <Sheet title="Create rule set" label="Create rule set" testId="create-rule-set">
            <ActionForm action={createRuleSet} submit="Create" testId="create-rule-set">
              <Field label="Name" rule={RULE_SET_NAME} taken={names} unique member="RuleSetName">
                <input name="name" required autoFocus />
              </Field>
              {names.length > 0 && (
                <Field label="Copy rules from" member="OriginalRuleSetName">
                  <select name="from" defaultValue="">
                    <option value="">Start empty</option>
                    {names.map((n) => (
                      <option key={n}>{n}</option>
                    ))}
                  </select>
                </Field>
              )}
              <label className="check">
                <input type="checkbox" name="activate" defaultChecked={!active} /> Make it the active rule set
              </label>
            </ActionForm>
          </Sheet>
        }
      >
        {!active && sets.length > 0 && <div className="banner">No rule set is active: SES rejects mail it receives.</div>}
        <List
          label="Rule sets"
          empty={<Empty icon={ICONS.email} />}
          rows={sets.map((s) => ({
            key: s.Name!,
            icon: <Inbox size={18} aria-hidden />,
            title: s.Name,
            href: ruleSetHref(s.Name),
            meta: (
              <>
                {s.Name === active && <Status tone="good">active</Status>}
                <span>{ago(s.CreatedTimestamp)}</span>
              </>
            ),
            actions: (
              <>
                {s.Name === active ? (
                  <ActionForm action={setActiveRuleSet.bind(null, null)} submit={`Deactivate ${s.Name}`} icon={<X size={15} />} />
                ) : (
                  <ActionForm action={setActiveRuleSet.bind(null, s.Name!)} submit={`Activate ${s.Name}`} icon={<Check size={15} />} />
                )}
                <ActionForm action={deleteRuleSet.bind(null, s.Name!, false)} submit={`Delete ${s.Name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${s.Name}?`} />
              </>
            ),
          }))}
        />
      </Section>
      <Section
        title="IP address filters"
        count={filters.length}
        plain
        actions={
          <Sheet title="Create IP address filter" label="Create IP address filter" testId="create-filter">
            <ActionForm action={createFilter} submit="Create" testId="create-filter">
              <Field label="Name" rule={{ ...RULE_SET_NAME, ...ReceiptFilter.Filter.fields?.Name }} taken={filters.map((f) => f.Name!)} unique>
                <input name="filterName" required />
              </Field>
              <div className="form-row">
                <Field label="IP address or range" rule={{ ...ReceiptFilter.Filter.fields?.IpFilter.fields?.Cidr, format: "cidr" }} member="Cidr">
                  <input name="cidr" required placeholder="10.0.0.0/24" />
                </Field>
                <Field label="Policy" member="Policy">
                  <select name="policy" defaultValue="Block">
                    <option>Block</option>
                    <option>Allow</option>
                  </select>
                </Field>
              </div>
            </ActionForm>
          </Sheet>
        }
      >
        <List
          label="IP filters"
          empty={<Empty icon={ICONS.email} />}
          rows={filters.map((f) => ({
            key: f.Name!,
            icon: f.IpFilter?.Policy === "Block" ? <Ban size={16} aria-hidden /> : <Check size={16} aria-hidden />,
            title: f.Name,
            subtitle: f.IpFilter?.Cidr,
            meta: <Pill tone={f.IpFilter?.Policy === "Block" ? "bad" : "info"}>{f.IpFilter?.Policy}</Pill>,
            actions: <ActionForm action={deleteFilter.bind(null, f.Name!)} submit={`Delete ${f.Name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${f.Name}?`} />,
          }))}
        />
      </Section>
      <Section
        title="Received mail"
        count={received.length}
        plain
        actions={
          <Sheet title="Receive a test message" label="Receive a test message" icon={<Inbox size={16} />} testId="receive-test">
            <ActionForm action={receiveTest} submit="Deliver" testId="receive-test">
              <div className="form-row">
                <Field label="From" rule={{ required: true, format: "email" }}>
                  <input name="from" required defaultValue="sender@example.net" />
                </Field>
                <Field label="To" rule={{ required: true, format: "emails" }}>
                  <input name="to" required placeholder="support@your-domain.com" />
                </Field>
              </div>
              <Field label="Subject">
                <input name="subject" />
              </Field>
              <textarea name="body" aria-label="Body" rows={4} />
            </ActionForm>
          </Sheet>
        }
      >
        <List
          label="Received mail"
          empty={<Empty icon={ICONS.email} />}
          rows={[...received].reverse().map((m) => ({
            key: m.MessageId,
            icon: <Inbox size={18} aria-hidden />,
            title: m.Subject || "(no subject)",
            subtitle: (
              <details>
                <summary>
                  {m.Source} → {m.Recipients.join(", ")}
                  {m.MatchedRules.length ? ` · ${m.RuleSet}: ${m.MatchedRules.join(", ")}` : " · no rule matched"}
                </summary>
                {m.Actions.length > 0 && (
                  <ul>
                    {m.Actions.map((a, i) => (
                      <li key={i}>{a}</li>
                    ))}
                  </ul>
                )}
                <pre className="code">{m.RawData}</pre>
              </details>
            ),
            meta: (
              <>
                {m.Actions.some((a) => /fail/i.test(a)) && <Status tone="bad">action failed</Status>}
                <span>{ago(m.Timestamp)}</span>
              </>
            ),
          }))}
        />
      </Section>
    </>
  );
}

export async function Suppression({ account }: { account: GetAccountCommandOutput | null }) {
  const list = await load(async () => {
    const client = await ses();
    return all(
      (NextToken) => client.send(new ListSuppressedDestinationsCommand({ NextToken })),
      (r) => r.SuppressedDestinationSummaries,
      (r) => r.NextToken,
    );
  });
  const reasons = account?.SuppressionAttributes?.SuppressedReasons ?? [];
  return (
    <>
      <Section
        title="Account suppression"
        plain
        actions={
          <Sheet title="Account suppression" label="Edit account suppression" testId="account-suppression">
            <ActionForm action={setAccountSuppression} submit="Save" testId="account-suppression">
              <fieldset className="checks">
                <legend>Add addresses to the list when they</legend>
                <label className="check">
                  <input type="checkbox" name="reason" value="BOUNCE" defaultChecked={reasons.includes("BOUNCE")} /> Hard bounce
                </label>
                <label className="check">
                  <input type="checkbox" name="reason" value="COMPLAINT" defaultChecked={reasons.includes("COMPLAINT")} /> Complain
                </label>
              </fieldset>
            </ActionForm>
          </Sheet>
        }
      >
        <p className="muted">{reasons.length ? `Suppressing on ${reasons.map((r) => r.toLowerCase()).join(" and ")}.` : "The account adds nothing to the list by itself."}</p>
      </Section>
      <Section
        title="Suppressed addresses"
        count={list.ok ? list.value.length : undefined}
        plain
        actions={
          <Sheet title="Add to suppression list" label="Add address" icon={<ShieldBan size={16} />} testId="suppress">
            <ActionForm action={suppress} submit="Add" testId="suppress">
              <Field label="Email address" rule={{ ...PutSuppressedDestination.EmailAddress, format: "email" }} member="EmailAddress">
                <input name="email" required />
              </Field>
              <Field label="Reason" rule={PutSuppressedDestination.Reason}>
                <select name="reason" defaultValue="BOUNCE">
                  <option value="BOUNCE">Bounce</option>
                  <option value="COMPLAINT">Complaint</option>
                </select>
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {list.ok ? (
          <List
            label="Suppressed addresses"
            empty={<Empty icon={ICONS.email} />}
            rows={list.value.map((d) => ({
              key: d.EmailAddress!,
              icon: <ShieldBan size={16} aria-hidden />,
              title: d.EmailAddress,
              meta: (
                <>
                  <Pill>{d.Reason?.toLowerCase()}</Pill>
                  <span>{ago(d.LastUpdateTime)}</span>
                </>
              ),
              actions: <ActionForm action={unsuppress.bind(null, d.EmailAddress!)} submit={`Remove ${d.EmailAddress}`} icon={<X size={15} />} tone="danger" />,
            }))}
          />
        ) : (
          <ErrorNotice error={list.error} />
        )}
      </Section>
    </>
  );
}

const linkify = (body: string, link?: string) => {
  if (!link || !body.includes(link)) return body;
  const [before, ...after] = body.split(link);
  return (
    <>
      {before}
      <a href={link} target="_blank" rel="noreferrer">
        {link}
      </a>
      {after.join(link)}
    </>
  );
};

export async function Outbox() {
  const outbox = await load(sesMail);
  if (!outbox.ok) return <ErrorNotice error={outbox.error} />;
  return (
    <Section
      title="Sent"
      count={outbox.value.length}
      plain
      actions={<ActionForm action={clearOutbox} submit="Clear this Region's sent mail" icon={<Eraser size={16} aria-hidden />} tone="danger" confirm="Clear the sent mail of this account and Region?" />}
    >
      <List
        label="Outbox"
        empty={<Empty icon={ICONS.email} />}
        rows={[...outbox.value].reverse().map((m) => {
          const body = m.Body.text_part ?? (m.Body.html_part ? htmlText(m.Body.html_part) : m.RawData);
          const cc = m.Destination.CcAddresses ?? [];
          const bcc = m.Destination.BccAddresses ?? [];
          return {
            key: m.Id,
            icon: <AwsIcon icon={ICONS.email} size={24} />,
            title: m.Subject || m.Template || "(no subject)",
            subtitle: (
              <details>
                <summary>
                  {m.Source} → {m.Destination.ToAddresses.join(", ")}
                  {cc.length > 0 && ` · cc ${cc.join(", ")}`}
                  {bcc.length > 0 && ` · bcc ${bcc.join(", ")}`}
                </summary>
                {m.VerificationLink && (
                  <p>
                    <a href={m.VerificationLink} target="_blank" rel="noreferrer">
                      Open the verification link
                    </a>
                  </p>
                )}
                <pre className="code">{linkify(body, m.VerificationLink)}</pre>
                {m.Body.html_part && (
                  <details>
                    <summary>HTML source</summary>
                    <pre className="code">{m.Body.html_part}</pre>
                  </details>
                )}
              </details>
            ),
            meta: (
              <>
                {m.Kind !== "Email" && <Pill tone="info">{m.Kind}</Pill>}
                {m.Template && <Pill title="Template">{m.Template}</Pill>}
                {m.ConfigurationSetName && <Pill title="Configuration set">{m.ConfigurationSetName}</Pill>}
                <span>{ago(m.Timestamp)}</span>
              </>
            ),
            actions: <ActionForm action={deleteMail.bind(null, m.Id)} submit="Delete message" icon={<X size={15} />} tone="danger" />,
          };
        })}
      />
    </Section>
  );
}

export const accountOf = () => load(async () => (await ses()).send(new GetAccountCommand({})));

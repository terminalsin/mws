import { GetIdentityNotificationAttributesCommand } from "@aws-sdk/client-ses";
import { GetEmailIdentityCommand } from "@aws-sdk/client-sesv2";
import { frameInfo, load } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, Empty, ErrorNotice, Field, List, Page, Pill, Section, Segments, Sheet, Specs, Status, Table } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { CreateEmailIdentityPolicy, PutEmailIdentityMailFromAttributes } from "@mws-dashboard/ui/model/sesv2";
import { BadgeCheck, Bell, FileKey, Forward, KeyRound, Mail, Pencil, Plus, Settings, Trash2, Upload, X } from "lucide-react";
import type { Metadata } from "next";

import { configSets, topics } from "../../../lib/choices";
import { configSetHref, ICONS, sesV1, ses, VERIFICATION_TONE, verificationLabel } from "../../../lib/clients";
import { identityRecords, zoneFor } from "../../../lib/dns";
import {
  createIdentityPolicy,
  deleteIdentity,
  deleteIdentityPolicy,
  publishRecords,
  setDkimKeyLength,
  setDkimSigning,
  setFeedback,
  setIdentityConfigSet,
  setMailFrom,
  setNotifications,
  verifyIdentity,
} from "../actions";

export const metadata: Metadata = { title: "Identity" };

type Props = { searchParams: Promise<{ name?: string; tab?: string }> };

const NOTIFICATION_TYPES = ["Bounce", "Complaint", "Delivery"] as const;
const topicHref = (arn: string) => `/sns/topic?arn=${encodeURIComponent(arn)}`;

export default async function Identity({ searchParams }: Props) {
  const { name = "", tab = "verification" } = await searchParams;
  const back = { href: "/ses", label: "Identities" };
  const data = await load(async () => {
    const [identity, notify, records] = await Promise.all([
      (await ses()).send(new GetEmailIdentityCommand({ EmailIdentity: name })),
      (await sesV1())
        .send(new GetIdentityNotificationAttributesCommand({ Identities: [name] }))
        .then((r) => r.NotificationAttributes?.[name])
        .catch(() => undefined),
      identityRecords(name),
    ]);
    const domain = name.includes("@") ? name.split("@")[1] : name;
    const [zone, sets, snsTopics, info] = await Promise.all([records.length ? zoneFor(domain).catch(() => undefined) : undefined, configSets(), topics(), frameInfo()]);
    return { identity, notify, records, zone, sets, snsTopics, identityArn: `arn:aws:ses:${info.region}:${info.account}:identity/${name}` };
  });
  if (!data.ok) {
    return (
      <Page title={name || "Identity"} icon={ICONS.email} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { identity: i, notify, records, zone, sets, snsTopics, identityArn } = data.value;
  const domain = i.IdentityType === "DOMAIN";
  const dkim = i.DkimAttributes;
  const mailFrom = i.MailFromAttributes;
  const policies = Object.entries(i.Policies ?? {});
  const href = (t: string) => `/ses/identity?name=${encodeURIComponent(name)}${t === "verification" ? "" : `&tab=${t}`}`;
  const tabs = [
    { id: "verification", label: domain ? "DNS records" : "Verification" },
    { id: "auth", label: "Authentication" },
    { id: "notifications", label: "Notifications" },
    { id: "policies", label: "Authorization", count: policies.length },
  ];
  const settling = i.VerificationStatus === "PENDING" || dkim?.Status === "PENDING" || mailFrom?.MailFromDomainStatus === "PENDING";
  const topicFor = (t: (typeof NOTIFICATION_TYPES)[number]) => notify?.[`${t}Topic` as "BounceTopic"];
  return (
    <Page
      title={name}
      icon={ICONS.email}
      back={back}
      subtitle={domain ? "Domain identity" : "Email address identity"}
      actions={
        <>
          {i.VerificationStatus !== "SUCCESS" && (
            <ActionForm action={verifyIdentity.bind(null, name)} submit="Verify (MWS shortcut: skips the link or DNS records)" icon={<BadgeCheck size={16} />} testId="force-verify" />
          )}
          <ActionForm action={deleteIdentity.bind(null, name, true)} submit="Delete identity" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} testId="delete-identity" />
        </>
      }
    >
      {settling && <LiveRefresh every={5000} />}
      <Specs
        items={[
          {
            label: "Identity status",
            icon: <BadgeCheck size={15} />,
            value: <Status tone={VERIFICATION_TONE[i.VerificationStatus ?? "PENDING"] ?? "warn"}>{verificationLabel(i.VerificationStatus)}</Status>,
          },
          domain && dkim && { label: "DKIM", icon: <KeyRound size={15} />, value: <Status tone={VERIFICATION_TONE[dkim.Status ?? "PENDING"] ?? "warn"}>{verificationLabel(dkim.Status)}</Status> },
          mailFrom?.MailFromDomain && {
            label: "MAIL FROM",
            icon: <Mail size={15} />,
            value: <Status tone={mailFrom.MailFromDomainStatus === "SUCCESS" ? "good" : mailFrom.MailFromDomainStatus === "FAILED" ? "bad" : "warn"}>{`${mailFrom.MailFromDomain} · ${mailFrom.MailFromDomainStatus?.toLowerCase()}`}</Status>,
          },
          { label: "Sending", icon: <Mail size={15} />, value: i.VerifiedForSendingStatus ? "Verified for sending" : "Not yet" },
          i.ConfigurationSetName && { label: "Default configuration set", icon: <Settings size={15} />, value: <a href={configSetHref(i.ConfigurationSetName)}>{i.ConfigurationSetName}</a> },
        ]}
      />
      {i.VerificationStatus === "FAILED" && (
        <div className="banner error" role="alert">
          Verification failed: SES gave up waiting {domain ? "for the DNS records (72 hours)" : "for the link to be followed (24 hours)"}. Delete the identity and create it again to restart.
        </div>
      )}
      <Segments label="Identity" items={tabs.map((t) => ({ label: t.label, href: href(t.id), active: t.id === tab, count: t.count }))} />
      {tab === "verification" &&
        (records.length ? (
          <Section
            title="DNS records"
            count={records.length}
            plain
            actions={
              zone ? (
                <ActionForm action={publishRecords.bind(null, name)} submit={`Publish records to Route 53 (${zone.Name})`} icon={<Upload size={16} />} testId="publish-records" />
              ) : undefined
            }
          >
            {!zone && <p className="muted">No Route 53 public hosted zone holds this domain: publish these records with your DNS provider.</p>}
            {zone && (
              <p className="muted">
                Hosted zone <a href={`/route53/zone?id=${zone.Id!.split("/").pop()}`}>{zone.Name}</a>
              </p>
            )}
            <Table
              label="DNS records"
              rowKey={(r) => `${r.name}|${r.type}|${r.value}`}
              rows={records}
              columns={[
                { header: "Purpose", cell: (r) => r.purpose },
                { header: "Type", cell: (r) => r.type },
                { header: "Name", cell: (r) => <code>{r.name}</code> },
                { header: "Value", cell: (r) => <code>{r.value}</code> },
              ]}
            />
          </Section>
        ) : (
          <Section title="Verification" plain>
            <p className="muted">
              {i.VerificationStatus === "SUCCESS" ? "Verified: the address owner followed the link SES mailed." : "SES mailed this address a verification link: open it from "}
              {i.VerificationStatus !== "SUCCESS" && <a href="/ses?tab=outbox">Sent mail</a>}.
            </p>
          </Section>
        ))}
      {tab === "auth" && (
        <>
          {domain && dkim && (
            <Section
              title="DomainKeys Identified Mail (DKIM)"
              plain
              actions={
                <>
                  <Sheet title="DKIM signing key" label="Edit DKIM key length" icon={<FileKey size={16} />} testId="dkim-key">
                    <ActionForm action={setDkimKeyLength.bind(null, name)} submit="Save" testId="dkim-key">
                      <Field label="Next signing key length" member="NextSigningKeyLength">
                        <select name="keyLength" defaultValue={dkim.NextSigningKeyLength ?? dkim.CurrentSigningKeyLength ?? "RSA_2048_BIT"}>
                          <option value="RSA_2048_BIT">RSA 2048-bit</option>
                          <option value="RSA_1024_BIT">RSA 1024-bit</option>
                        </select>
                      </Field>
                    </ActionForm>
                  </Sheet>
                  <ActionForm
                    action={setDkimSigning.bind(null, name, !dkim.SigningEnabled)}
                    submit={dkim.SigningEnabled ? "Turn DKIM signing off" : "Turn DKIM signing on"}
                    icon={<KeyRound size={16} />}
                    testId="dkim-signing"
                  />
                </>
              }
            >
              <Specs
                items={[
                  { label: "Signing", icon: <KeyRound size={15} />, value: dkim.SigningEnabled ? "On" : "Off" },
                  { label: "Origin", icon: <KeyRound size={15} />, value: dkim.SigningAttributesOrigin === "EXTERNAL" ? "Bring your own key" : "Easy DKIM" },
                  dkim.CurrentSigningKeyLength && { label: "Key length", icon: <FileKey size={15} />, value: dkim.CurrentSigningKeyLength.replace(/RSA_(\d+)_BIT/, "RSA $1-bit") },
                ]}
              />
            </Section>
          )}
          <Section
            title="Custom MAIL FROM domain"
            plain
            actions={
              <Sheet title="Custom MAIL FROM domain" label="Edit MAIL FROM domain" icon={<Pencil size={16} />} testId="mail-from">
                <ActionForm action={setMailFrom.bind(null, name)} submit="Save" testId="mail-from">
                  <Field label="MAIL FROM domain (empty to remove)" rule={{ ...PutEmailIdentityMailFromAttributes.MailFromDomain, format: "domain" }} member="MailFromDomain">
                    <input name="mailFrom" defaultValue={mailFrom?.MailFromDomain ?? ""} placeholder={`mail.${name.split("@").pop()}`} />
                  </Field>
                  <Field label="If the MX record is missing" rule={PutEmailIdentityMailFromAttributes.BehaviorOnMxFailure} member="BehaviorOnMxFailure">
                    <select name="mxFailure" defaultValue={mailFrom?.BehaviorOnMxFailure ?? "USE_DEFAULT_VALUE"}>
                      <option value="USE_DEFAULT_VALUE">Use amazonses.com</option>
                      <option value="REJECT_MESSAGE">Reject the message</option>
                    </select>
                  </Field>
                </ActionForm>
              </Sheet>
            }
          >
            <p className="muted">
              {mailFrom?.MailFromDomain
                ? `${mailFrom.MailFromDomain} (${mailFrom.MailFromDomainStatus?.toLowerCase()}); on MX failure: ${mailFrom.BehaviorOnMxFailure === "REJECT_MESSAGE" ? "reject" : "use amazonses.com"}`
                : "Mail goes out with an amazonses.com MAIL FROM."}
            </p>
          </Section>
          <Section
            title="Default configuration set"
            plain
            actions={
              <Sheet title="Default configuration set" label="Edit default configuration set" icon={<Settings size={16} />} testId="identity-config-set">
                <ActionForm action={setIdentityConfigSet.bind(null, name)} submit="Save" testId="identity-config-set">
                  <Field label="Configuration set" member="ConfigurationSetName">
                    <select name="configSet" defaultValue={i.ConfigurationSetName ?? ""}>
                      <option value="">None</option>
                      {sets.map((s) => (
                        <option key={s}>{s}</option>
                      ))}
                    </select>
                  </Field>
                </ActionForm>
              </Sheet>
            }
          >
            <p className="muted">{i.ConfigurationSetName ? `Sends without a configuration set use ${i.ConfigurationSetName}.` : "None: sends use only the configuration set they name."}</p>
          </Section>
        </>
      )}
      {tab === "notifications" && (
        <>
          <Section
            title="Feedback notifications"
            plain
            actions={
              <>
                <Sheet title="SNS topics" label="Edit notification topics" icon={<Bell size={16} />} testId="notification-topics">
                  <ActionForm action={setNotifications.bind(null, name)} submit="Save" testId="notification-topics">
                    {NOTIFICATION_TYPES.map((t) => (
                      <div className="form-row" key={t}>
                        <Field label={`${t} topic`} member="SnsTopic">
                          <select name={`topic:${t}`} defaultValue={topicFor(t) ?? ""}>
                            <option value="">None</option>
                            {snsTopics.map((arn) => (
                              <option key={arn} value={arn}>
                                {arn.split(":").pop()}
                              </option>
                            ))}
                          </select>
                        </Field>
                        <input type="hidden" name={`was:${t}`} value={topicFor(t) ?? ""} />
                        <label className="check">
                          <input type="checkbox" name={`headers:${t}`} defaultChecked={notify?.[`HeadersIn${t}NotificationsEnabled` as "HeadersInBounceNotificationsEnabled"]} /> Include original headers
                        </label>
                      </div>
                    ))}
                  </ActionForm>
                </Sheet>
                <ActionForm
                  action={setFeedback.bind(null, name, !i.FeedbackForwardingStatus)}
                  submit={i.FeedbackForwardingStatus ? "Turn email feedback forwarding off" : "Turn email feedback forwarding on"}
                  icon={<Forward size={16} />}
                  testId="feedback-forwarding"
                />
              </>
            }
          >
            <List
              label="Notification topics"
              rows={[
                ...NOTIFICATION_TYPES.map((t) => {
                  const arn = topicFor(t);
                  return {
                    key: t,
                    icon: <Bell size={16} aria-hidden />,
                    title: t,
                    subtitle: arn ?? "No topic",
                    href: arn ? topicHref(arn) : undefined,
                    meta: notify?.[`HeadersIn${t}NotificationsEnabled` as "HeadersInBounceNotificationsEnabled"] ? <Pill>with headers</Pill> : undefined,
                  };
                }),
                {
                  key: "forwarding",
                  icon: <Forward size={16} aria-hidden />,
                  title: "Email feedback forwarding",
                  subtitle: i.FeedbackForwardingStatus ? "Bounces and complaints are mailed to the sender" : "Off",
                  meta: <Status tone={i.FeedbackForwardingStatus ? "good" : "neutral"}>{i.FeedbackForwardingStatus ? "on" : "off"}</Status>,
                },
              ]}
            />
          </Section>
        </>
      )}
      {tab === "policies" && (
        <Section
          title="Sending authorization policies"
          count={policies.length}
          plain
          actions={
            <Sheet title="Create policy" label="Create policy" icon={<Plus size={16} />} testId="create-identity-policy">
              <ActionForm action={createIdentityPolicy.bind(null, name)} submit="Create" testId="create-identity-policy">
                <Field label="Policy name" rule={{ ...CreateEmailIdentityPolicy.PolicyName, generate: "name" }} taken={policies.map(([n]) => n)} unique member="PolicyName">
                  <input name="policyName" required />
                </Field>
                <Field label="Policy" rule={CreateEmailIdentityPolicy.Policy} format="json" member="Policy">
                  <textarea
                    name="policy"
                    rows={10}
                    className="code-editor"
                    defaultValue={JSON.stringify(
                      { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: "111122223333" }, Action: ["ses:SendEmail", "ses:SendRawEmail"], Resource: identityArn }] },
                      null,
                      2,
                    )}
                  />
                </Field>
              </ActionForm>
            </Sheet>
          }
        >
          {policies.length ? (
            policies.map(([policyName, doc]) => (
              <Section
                key={policyName}
                title={policyName}
                plain
                actions={<ActionForm action={deleteIdentityPolicy.bind(null, name, policyName)} submit={`Delete ${policyName}`} icon={<X size={15} />} tone="danger" confirm={`Delete ${policyName}?`} />}
              >
                <CodeBlock value={doc} label={policyName} />
              </Section>
            ))
          ) : (
            <Empty icon={ICONS.email} />
          )}
        </Section>
      )}
    </Page>
  );
}

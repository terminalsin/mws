import { ListAccountsCommand, ListAWSServiceAccessForOrganizationCommand, ListDelegatedAdministratorsCommand, ListDelegatedServicesForAccountCommand } from "@aws-sdk/client-organizations";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Section, Sheet, SERVICES } from "@mws-dashboard/ui";
import { EnableAWSServiceAccess, RegisterDelegatedAdministrator } from "@mws-dashboard/ui/model/organizations";
import { Plus, PowerOff, UserCog, UserMinus } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, organizations } from "../../../lib/clients";
import { deregisterDelegatedAdmin, enableServiceAccess, registerDelegatedAdmin, setServiceAccess } from "../actions";

export const metadata: Metadata = { title: "Services" };

/** Service principals that commonly integrate with Organizations. */
const KNOWN = [
  "sso.amazonaws.com",
  "guardduty.amazonaws.com",
  "securityhub.amazonaws.com",
  "cloudtrail.amazonaws.com",
  "config.amazonaws.com",
  "ram.amazonaws.com",
  "servicequotas.amazonaws.com",
  "member.org.stacksets.cloudformation.amazonaws.com",
  "ipam.amazonaws.com",
  "access-analyzer.amazonaws.com",
  "backup.amazonaws.com",
  "account.amazonaws.com",
];

const iconOf = (principal: string) => {
  const name = principal.split(".")[0];
  const id = name === "sso" ? "identitycenter" : name;
  return SERVICES.find((s) => s.id === id || s.endpoints.includes(name))?.icon ?? ICONS.organizations;
};

/** Trusted access and delegated administrators: which AWS services may act
 * across the organization, and which member account runs each. */
export default async function Services() {
  const data = await load(async () => {
    const client = await organizations();
    const [access, admins, accounts] = await Promise.all([
      all((NextToken) => client.send(new ListAWSServiceAccessForOrganizationCommand({ NextToken })), (r) => r.EnabledServicePrincipals, (r) => r.NextToken),
      all((NextToken) => client.send(new ListDelegatedAdministratorsCommand({ NextToken })), (r) => r.DelegatedAdministrators, (r) => r.NextToken),
      all((NextToken) => client.send(new ListAccountsCommand({ NextToken })), (r) => r.Accounts, (r) => r.NextToken),
    ]);
    const services = await Promise.all(
      admins.map(async (a) => ({
        a,
        services: await all((NextToken) => client.send(new ListDelegatedServicesForAccountCommand({ AccountId: a.Id, NextToken })), (r) => r.DelegatedServices, (r) => r.NextToken),
      })),
    );
    return { access, services, accounts };
  });
  const back = { href: "/organizations", label: "AWS accounts" };
  if (!data.ok) {
    return (
      <Page title="Services" back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { access, services, accounts } = data.value;
  const enabled = new Set(access.map((s) => s.ServicePrincipal));
  return (
    <Page title="Services" back={back}>
      <Section
        title="Trusted access"
        count={access.length}
        plain
        actions={
          <Sheet title="Enable trusted access" label="Enable trusted access" icon={<Plus size={16} />} testId="enable-service-access">
            <ActionForm action={enableServiceAccess} submit="Enable" testId="enable-service-access">
              <Field label="Service principal" rule={EnableAWSServiceAccess.ServicePrincipal} known={KNOWN.filter((k) => !enabled.has(k))}>
                <input name="principal" list="service-principals" required placeholder="guardduty.amazonaws.com" />
              </Field>
              <datalist id="service-principals">
                {KNOWN.map((k) => (
                  <option key={k} value={k} />
                ))}
              </datalist>
            </ActionForm>
          </Sheet>
        }
      >
        <List
          label="Trusted access"
          empty={<Empty icon={ICONS.organizations} />}
          rows={access.map((s) => ({
            key: s.ServicePrincipal!,
            icon: <AwsIcon icon={iconOf(s.ServicePrincipal!)} size={22} />,
            title: s.ServicePrincipal,
            meta: ago(s.DateEnabled),
            actions: (
              <ActionForm
                action={setServiceAccess.bind(null, s.ServicePrincipal!, false)}
                submit={`Disable ${s.ServicePrincipal}`}
                icon={<PowerOff size={15} />}
                tone="danger"
                confirm={`Disable trusted access for ${s.ServicePrincipal}?`}
              />
            ),
          }))}
        />
      </Section>
      <Section
        title="Delegated administrators"
        count={services.length}
        plain
        actions={
          <Sheet title="Register delegated administrator" label="Register delegated administrator" icon={<UserCog size={16} />} testId="register-delegated-admin">
            <ActionForm action={registerDelegatedAdmin} submit="Register" testId="register-delegated-admin">
              <Field label="Account">
                <select name="account" required>
                  {accounts.map((a) => (
                    <option key={a.Id} value={a.Id}>
                      {a.Name} ({a.Id})
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Service principal" rule={RegisterDelegatedAdministrator.ServicePrincipal} known={[...enabled].filter((x): x is string => !!x)}>
                <input name="principal" list="enabled-principals" required />
              </Field>
              <datalist id="enabled-principals">
                {[...enabled].map((k) => (
                  <option key={k} value={k} />
                ))}
              </datalist>
            </ActionForm>
          </Sheet>
        }
      >
        <List
          label="Delegated administrators"
          empty={<Empty icon={ICONS.account} />}
          rows={services.flatMap(({ a, services }) =>
            services.map((s) => ({
              key: `${a.Id}:${s.ServicePrincipal}`,
              icon: <AwsIcon icon={iconOf(s.ServicePrincipal!)} size={22} />,
              title: s.ServicePrincipal,
              subtitle: `${a.Name} · ${a.Id}`,
              href: `/organizations/accounts/${a.Id}`,
              meta: <Pill>{ago(s.DelegationEnabledDate)}</Pill>,
              actions: (
                <ActionForm
                  action={deregisterDelegatedAdmin.bind(null, a.Id!, s.ServicePrincipal!)}
                  submit={`Deregister ${a.Name} for ${s.ServicePrincipal}`}
                  icon={<UserMinus size={15} />}
                  tone="danger"
                  confirm={`Deregister ${a.Name} as administrator for ${s.ServicePrincipal}?`}
                />
              ),
            })),
          )}
        />
      </Section>
    </Page>
  );
}

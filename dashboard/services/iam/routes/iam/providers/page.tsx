import { GetOpenIDConnectProviderCommand, ListOpenIDConnectProvidersCommand, ListSAMLProvidersCommand } from "@aws-sdk/client-iam";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Sheet } from "@mws-dashboard/ui";
import { CreateSAMLProvider } from "@mws-dashboard/ui/model/iam";
import { Fingerprint, Plus, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { iam } from "../../../lib/clients";
import { OidcFields } from "../../../lib/forms.tsx";
import { oidcIcon } from "../../../lib/presets";
import { createOidcProvider, createSamlProvider, deleteProvider } from "../actions";

export const metadata: Metadata = { title: "Identity providers" };

/** OIDC and SAML identity providers that federated roles trust. */
export default async function Providers() {
  const data = await load(async () => {
    const client = await iam();
    const [oidc, saml] = await Promise.all([
      client.send(new ListOpenIDConnectProvidersCommand({})).then((r) => r.OpenIDConnectProviderList ?? []),
      client.send(new ListSAMLProvidersCommand({})).then((r) => r.SAMLProviderList ?? []),
    ]);
    const details = await Promise.all(oidc.map((p) => client.send(new GetOpenIDConnectProviderCommand({ OpenIDConnectProviderArn: p.Arn }))));
    return { oidc: oidc.map((p, i) => ({ arn: p.Arn!, ...details[i] })), saml };
  });
  const back = { href: "/iam?tab=roles", label: "Roles" };
  const actions = (
    <>
      <Sheet title="Add OpenID Connect provider" label="Add OpenID Connect provider" icon={<Plus size={16} />} testId="create-oidc-provider">
        <ActionForm action={createOidcProvider} submit="Add provider" testId="create-oidc-provider">
          <OidcFields urls={data.ok ? data.value.oidc.map((p) => p.Url ?? "") : []} />
        </ActionForm>
      </Sheet>
      <Sheet title="Add SAML provider" label="Add SAML provider" icon={<Fingerprint size={16} />} testId="create-saml-provider">
        <ActionForm action={createSamlProvider} submit="Add provider" testId="create-saml-provider">
          <Field label="Name" rule={CreateSAMLProvider.Name} unique>
            <input name="name" required />
          </Field>
          <Field label="Metadata document" rule={CreateSAMLProvider.SAMLMetadataDocument}>
            <textarea name="metadata" rows={10} required placeholder="<EntityDescriptor ...>" />
          </Field>
        </ActionForm>
      </Sheet>
    </>
  );
  if (!data.ok) {
    return (
      <Page title="Identity providers" back={back} actions={actions}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { oidc, saml } = data.value;
  return (
    <Page title="Identity providers" back={back} actions={actions}>
      <List
        label="Identity providers"
        empty={<Empty icon="resource/AWSIdentityAccessManagementRole" action={actions} />}
        rows={[
          ...oidc.map((p) => ({
            key: p.arn,
            icon: oidcIcon(p.Url) ? <AwsIcon icon={oidcIcon(p.Url)!} size={22} /> : <Fingerprint size={18} />,
            title: p.Url,
            subtitle: (p.ClientIDList ?? []).join(", ") || "no audience",
            meta: (
              <>
                <Pill>OpenID Connect</Pill>
                <span>{ago(p.CreateDate)}</span>
              </>
            ),
            actions: <ActionForm action={deleteProvider.bind(null, p.arn)} submit={`Delete ${p.Url}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${p.Url}? Roles that trust it can no longer be assumed with its tokens.`} />,
          })),
          ...saml.map((p) => ({
            key: p.Arn!,
            icon: <Fingerprint size={18} />,
            title: p.Arn!.split("/").pop(),
            subtitle: p.ValidUntil ? `valid until ${new Date(p.ValidUntil).toISOString().slice(0, 10)}` : undefined,
            meta: (
              <>
                <Pill>SAML</Pill>
                <span>{ago(p.CreateDate)}</span>
              </>
            ),
            actions: <ActionForm action={deleteProvider.bind(null, p.Arn!)} submit={`Delete ${p.Arn!.split("/").pop()}`} icon={<Trash2 size={15} />} tone="danger" confirm="Delete this SAML provider?" />,
          })),
        ]}
      />
    </Page>
  );
}

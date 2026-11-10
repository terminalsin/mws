import { ListConnectorsCommand } from "@aws-sdk/client-pca-connector-scep";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { listAuthorities } from "../../../lib/cas";
import { ICONS, scep } from "../../../lib/clients";
import { CA_TONE, caName } from "../../../lib/pca";
import { createConnector } from "./actions";

export const metadata: Metadata = { title: "Connectors for SCEP" };

export default async function Connectors() {
  const c = await scep();
  const [list, cas] = await Promise.all([
    load(() => all((NextToken) => c.send(new ListConnectorsCommand({ NextToken })), (r) => r.Connectors, (r) => r.NextToken)),
    listAuthorities().catch(() => []),
  ]);
  const usable = cas.filter((ca) => ca.Status === "ACTIVE");
  const names = new Map(cas.map((ca) => [ca.Arn!, caName(ca)]));
  const create = (
    <Sheet title="Create connector" label="Create connector" testId="create-connector">
      <ActionForm action={createConnector} submit="Create" testId="create-connector">
        <Field label="Certificate authority" member="CertificateAuthorityArn">
          <select name="ca" required defaultValue={usable[0]?.Arn}>
            {usable.map((ca) => (
              <option key={ca.Arn} value={ca.Arn}>
                {caName(ca)} · {ca.Type === "ROOT" ? "root" : "subordinate"}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Connector type">
          <select name="type" defaultValue="GENERAL_PURPOSE">
            <option value="GENERAL_PURPOSE">General purpose (static challenge passwords)</option>
            <option value="INTUNE">Microsoft Intune</option>
          </select>
        </Field>
        <label className="check">
          <input type="checkbox" name="allow" defaultChecked /> Let the connector issue from this CA (adds a statement to the CA policy)
        </label>
        <details>
          <summary>Intune</summary>
          <div className="form-row">
            <Field label="Azure application ID" member="MobileDeviceManagement.Intune.AzureApplicationId">
              <input name="azureApp" />
            </Field>
            <Field label="Domain" member="MobileDeviceManagement.Intune.Domain" format="domain">
              <input name="azureDomain" placeholder="contoso.onmicrosoft.com" />
            </Field>
          </div>
        </details>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="Connectors for SCEP" icon={ICONS.pca} back={{ href: "/pca", label: "Private CAs" }} actions={create}>
      {list.ok ? (
        <List
          label="Connectors"
          empty={<Empty icon={ICONS.ca} action={usable.length ? create : undefined}>{usable.length ? undefined : "A connector needs an active private CA"}</Empty>}
          rows={list.value.map((k) => ({
            key: k.Arn!,
            icon: <AwsIcon icon={ICONS.ca} size={24} />,
            title: names.get(k.CertificateAuthorityArn!) ?? k.Arn!.split("/").pop(),
            subtitle: k.Endpoint ?? k.Arn,
            href: `/pca/connector?arn=${encodeURIComponent(k.Arn!)}`,
            meta: (
              <>
                <Pill>{k.Type === "INTUNE" ? "Intune" : "General purpose"}</Pill>
                <span>{ago(k.CreatedAt)}</span>
                <Status tone={CA_TONE[k.Status ?? ""] ?? "neutral"}>{k.Status?.toLowerCase()}</Status>
              </>
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={list.error} />
      )}
    </Page>
  );
}

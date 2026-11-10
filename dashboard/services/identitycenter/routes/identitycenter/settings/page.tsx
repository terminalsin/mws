import { load } from "@mws-dashboard/aws";
import { ActionForm, CopyButton, Empty, ErrorNotice, Facts, Field, Page, Section, Sheet, Status } from "@mws-dashboard/ui";
import { UpdateInstance } from "@mws-dashboard/ui/model/sso-admin";
import { Pencil } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS } from "../../../lib/clients";
import { instance as loadInstance } from "../../../lib/sso";
import { enableInstance, enablePermissionSets, updateInstance } from "../actions";
import { Links } from "../parts";

export const metadata: Metadata = { title: "Identity Center settings" };

/** The instance: where people sign in, and what it is. */
export default async function Settings() {
  const found = await load(loadInstance);
  if (!found.ok) {
    return (
      <Page title="Settings" actions={<Links />}>
        <ErrorNotice error={found.error} />
      </Page>
    );
  }
  if (!found.value) {
    return (
      <Page title="Settings">
        <Empty icon={ICONS.identitycenter} action={<ActionForm action={enableInstance} submit="Enable" testId="enable-identity-center" />}>
          Not enabled in this Region
        </Empty>
      </Page>
    );
  }
  const i = found.value;
  return (
    <Page
      title="Settings"
      icon={ICONS.identitycenter}
      subtitle={i.arn}
      actions={
        <>
          <Links />
          <Sheet title="Instance name" label="Edit instance name" icon={<Pencil size={16} />} testId="edit-instance">
            <ActionForm action={updateInstance.bind(null, i.arn)} submit="Save" testId="edit-instance">
              <Field label="Name" rule={UpdateInstance.Name}>
                <input name="name" required defaultValue={i.name} />
              </Field>
            </ActionForm>
          </Sheet>
        </>
      }
    >
      <Section title="Identity source">
        <Facts
          items={[
            ["Status", <Status key="s" tone={i.status === "ACTIVE" ? "good" : "info"}>{i.status?.toLowerCase() ?? "active"}</Status>],
            [
              "AWS access portal URL",
              <span key="u" style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                <code data-testid="start-url">{i.startUrl}</code>
                <CopyButton value={i.startUrl} label="Copy start URL" />
              </span>,
            ],
            ["Region", i.region],
            ["Identity source", "Identity Center directory"],
            ["Identity store ID", <code key="s">{i.store}</code>],
            i.name && ["Instance name", i.name],
            i.owner && [
              "Owner account",
              <Link key="o" href="/organizations">
                {i.owner}
              </Link>,
            ],
            [
              "Permission sets",
              i.permissionSets ? (
                "enabled"
              ) : (
                <ActionForm key="p" action={enablePermissionSets.bind(null, i.arn)} submit="Enable permission sets" testId="enable-permission-sets" />
              ),
            ],
            ["Created", i.created ? new Date(i.created).toISOString().slice(0, 10) : undefined],
          ]}
        />
      </Section>
      <Section title="Sign in from the AWS CLI">
        <pre className="code" aria-label="AWS CLI profile">{`[profile mws-sso]
sso_session = mws
sso_account_id = ${i.owner ?? "<account>"}
sso_role_name = <permission set>
endpoint_url = <MWS endpoint>

[sso-session mws]
sso_start_url = ${i.startUrl}
sso_region = ${i.region}`}</pre>
      </Section>
    </Page>
  );
}

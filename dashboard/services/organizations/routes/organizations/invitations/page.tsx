import { ListHandshakesForOrganizationCommand } from "@aws-sdk/client-organizations";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, Empty, ErrorNotice, Field, List, Page, Sheet, Status } from "@mws-dashboard/ui";
import { InviteAccountToOrganization } from "@mws-dashboard/ui/model/organizations";
import { Mail, UserPlus, X } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, organizations } from "../../../lib/clients";
import { cancelHandshake, inviteAccount } from "../actions";

export const metadata: Metadata = { title: "Invitations" };

const TONE: Record<string, "good" | "bad" | "info" | "neutral" | "warn"> = { OPEN: "info", REQUESTED: "info", ACCEPTED: "good", DECLINED: "bad", CANCELED: "neutral", EXPIRED: "warn" };

/** Invitations to join the organization, and other handshakes it sent. */
export default async function Invitations() {
  const data = await load(async () => {
    const client = await organizations();
    return all((NextToken) => client.send(new ListHandshakesForOrganizationCommand({ NextToken })), (r) => r.Handshakes, (r) => r.NextToken);
  });
  const back = { href: "/organizations", label: "AWS accounts" };
  const invite = (
    <Sheet title="Invite an AWS account" label="Invite an AWS account" icon={<UserPlus size={16} />} testId="invite-account">
      <ActionForm action={inviteAccount} submit="Send invitation" testId="invite-account">
        <Field label="Account ID or email address" hint="12 digits, or the account's root email">
          <input name="target" required />
        </Field>
        <Field label="Message" rule={InviteAccountToOrganization.Notes}>
          <textarea name="notes" rows={3} />
        </Field>
      </ActionForm>
    </Sheet>
  );
  if (!data.ok) {
    return (
      <Page title="Invitations" back={back} actions={invite}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  return (
    <Page title="Invitations" back={back} actions={invite}>
      <List
        label="Invitations"
        empty={<Empty icon={ICONS.organizations} />}
        rows={data.value
          .sort((a, b) => +new Date(b.RequestedTimestamp!) - +new Date(a.RequestedTimestamp!))
          .map((h) => {
            const target = h.Parties?.find((p) => p.Type !== "ORGANIZATION");
            const open = h.State === "OPEN" || h.State === "REQUESTED";
            return {
              key: h.Id!,
              icon: <Mail size={18} />,
              title: target?.Id ?? h.Id,
              subtitle: `${h.Action?.toLowerCase().replace(/_/g, " ")}${open ? ` · expires ${ago(h.ExpirationTimestamp)}` : ""}`,
              meta: (
                <>
                  <Status tone={TONE[h.State!] ?? "neutral"}>{h.State!.toLowerCase()}</Status>
                  <span>{ago(h.RequestedTimestamp)}</span>
                </>
              ),
              actions: open && <ActionForm action={cancelHandshake.bind(null, h.Id!)} submit={`Cancel invitation to ${target?.Id}`} icon={<X size={15} />} tone="danger" confirm="Cancel this invitation?" />,
            };
          })}
      />
    </Page>
  );
}

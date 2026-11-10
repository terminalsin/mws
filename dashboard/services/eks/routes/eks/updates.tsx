import type { Update } from "@aws-sdk/client-eks";
import { ago, when } from "@mws-dashboard/aws";
import { Empty, List, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { ArrowUpCircle } from "lucide-react";

import { UPDATE_TONE } from "../../lib/data";

const TYPE: Record<string, string> = {
  VersionUpdate: "Version update",
  EndpointAccessUpdate: "Endpoint access",
  LoggingUpdate: "Logging",
  ConfigUpdate: "Configuration",
  AssociateIdentityProviderConfig: "Identity provider",
  DisassociateIdentityProviderConfig: "Identity provider",
  AssociateEncryptionConfig: "Encryption",
  AddonUpdate: "Add-on update",
  AccessConfigUpdate: "Access configuration",
  UpgradePolicyUpdate: "Upgrade policy",
};

/** EKS updates (ListUpdates + DescribeUpdate): what changed, how it went
 * and why it failed. In-progress ones keep the page refreshing. */
export function UpdateRows({ updates, empty }: { updates: Update[]; empty?: boolean }) {
  return (
    <>
      <LiveRefresh when={updates.some((u) => u.status === "InProgress")} />
      <List
        label="Updates"
        empty={empty ? <Empty>No updates</Empty> : undefined}
        rows={updates.map((u) => ({
          key: u.id!,
          icon: <ArrowUpCircle size={18} aria-hidden />,
          title: `${TYPE[u.type ?? ""] ?? u.type}${u.params?.length ? `: ${u.params.map((p) => `${p.type} ${p.value}`).join(", ")}` : ""}`,
          subtitle: u.errors?.length ? <span className="row-subtitle">{u.errors.map((e) => `${e.errorCode}: ${e.errorMessage}`).join("; ")}</span> : u.id,
          meta: (
            <>
              <Status tone={UPDATE_TONE[u.status ?? ""] ?? "neutral"}>{u.status === "InProgress" ? "in progress" : (u.status?.toLowerCase() ?? "")}</Status>
              <span title={when(u.createdAt)}>{ago(u.createdAt)}</span>
            </>
          ),
        }))}
      />
    </>
  );
}

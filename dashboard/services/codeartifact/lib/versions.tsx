import type { PackageVersionStatus } from "@aws-sdk/client-codeartifact";
import { ActionForm } from "@mws-dashboard/ui";
import { Archive, Eye, EyeOff, Flame, Trash2 } from "lucide-react";

import { deleteVersion, disposeVersion, setVersionStatus } from "../routes/codeartifact/actions";
import type { PackageRef } from "./refs";

export const STATUS_TONE = { Published: "good", Unlisted: "neutral", Archived: "neutral", Disposed: "bad", Deleted: "bad", Unfinished: "warn" } as Record<
  string,
  "good" | "neutral" | "bad" | "warn"
>;

/** The status changes AWS allows from each status: Disposed and Unfinished
 * versions can only be disposed or deleted. */
const MOVES: Record<string, ("Published" | "Unlisted" | "Archived")[]> = {
  Published: ["Unlisted", "Archived"],
  Unlisted: ["Published", "Archived"],
  Archived: ["Published", "Unlisted"],
};

const ICON = { Published: <Eye size={15} />, Unlisted: <EyeOff size={15} />, Archived: <Archive size={15} /> };
const VERB = { Published: "Publish", Unlisted: "Unlist", Archived: "Archive" };

export function VersionActions({ pkg, version, status, back, name }: { pkg: PackageRef; version: string; status?: string; back?: string; name: string }) {
  const from = (status ?? "Published") as PackageVersionStatus;
  return (
    <>
      {(MOVES[from] ?? []).map((to) => (
        <ActionForm key={to} action={setVersionStatus.bind(null, pkg, version, from, to)} submit={`${VERB[to]} ${version}`} icon={ICON[to]} />
      ))}
      {from !== "Disposed" && (
        <ActionForm
          action={disposeVersion.bind(null, pkg, version, from)}
          submit={`Dispose ${version}`}
          icon={<Flame size={15} />}
          tone="danger"
          confirm={`Dispose ${name} ${version}? Its assets are deleted; the version stays listed as Disposed.`}
        />
      )}
      <ActionForm action={deleteVersion.bind(null, pkg, version, back ?? "")} submit={`Delete ${version}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${name} ${version}?`} />
    </>
  );
}

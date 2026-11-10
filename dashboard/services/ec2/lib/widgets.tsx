import "server-only";

import { ActionForm, Field, Segments, Sheet } from "@mws-dashboard/ui";
import { Tag } from "lucide-react";

import { saveTags } from "../routes/ec2/actions";
import { TAG_LINES } from "./rules";

export const EC2_TABS = [
  { id: "instances", label: "Instances" },
  { id: "templates", label: "Launch templates" },
  { id: "images", label: "AMIs" },
  { id: "volumes", label: "Volumes" },
  { id: "snapshots", label: "Snapshots" },
  { id: "groups", label: "Security groups" },
  { id: "keys", label: "Key pairs" },
] as const;

/** The EC2 console's sections, as line tabs (the sidebar lists the first ones). */
export function Ec2Nav({ tab }: { tab: string }) {
  return (
    <Segments
      label="EC2"
      items={EC2_TABS.map((t) => ({ label: t.label, href: t.id === "instances" ? "/ec2" : `/ec2?tab=${t.id}`, active: t.id === tab }))}
    />
  );
}

/** "Manage tags": every tag as a `key=value` line. */
export function TagsSheet({ id, tags }: { id: string; tags?: { Key?: string; Value?: string }[] }) {
  const lines = (tags ?? []).map((t) => `${t.Key}=${t.Value ?? ""}`).join("\n");
  return (
    <Sheet title="Manage tags" label="Manage tags" icon={<Tag size={16} />} testId="manage-tags">
      <ActionForm action={saveTags.bind(null, id)} submit="Save" testId="manage-tags">
        <Field label="Tags" rule={TAG_LINES} member="Tags" hint="One key=value per line">
          <textarea name="tags" rows={6} defaultValue={lines} className="code-editor" />
        </Field>
      </ActionForm>
    </Sheet>
  );
}

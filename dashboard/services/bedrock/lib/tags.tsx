import { ListTagsForResourceCommand } from "@aws-sdk/client-bedrock";
import { ActionForm, Field, Section, Sheet, Tags } from "@mws-dashboard/ui";
import { Tag as TagIcon } from "lucide-react";

import { saveTags } from "../routes/bedrock/jobs";
import { bedrock } from "./clients";

/** A resource's tags, with a sheet that edits them as `key=value` lines. */
export async function TagsSection({ arn, path }: { arn: string; path: string }) {
  const tags = await (await bedrock())
    .send(new ListTagsForResourceCommand({ resourceARN: arn }))
    .then((r) => r.tags ?? [])
    .catch(() => null);
  if (tags === null) return null;
  return (
    <Section
      title="Tags"
      count={tags.length}
      actions={
        <Sheet title="Manage tags" label="Manage tags" icon={<TagIcon size={15} />} testId="manage-tags">
          <ActionForm action={saveTags.bind(null, arn, path)} submit="Save" testId="manage-tags">
            <Field label="Tags" format="tags">
              <textarea name="tags" rows={5} defaultValue={tags.map((t) => `${t.key}=${t.value ?? ""}`).join("\n")} placeholder="team=ml" />
            </Field>
          </ActionForm>
        </Sheet>
      }
    >
      {tags.length ? <Tags tags={tags.map((t) => ({ Key: t.key, Value: t.value }))} /> : <span className="muted">No tags</span>}
    </Section>
  );
}

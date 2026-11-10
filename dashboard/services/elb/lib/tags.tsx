import { ActionForm, Empty, Field, List, Section, Sheet } from "@mws-dashboard/ui";
import { AddTags } from "@mws-dashboard/ui/model/elbv2";
import { Tag, X } from "lucide-react";

import { addTag, removeTag } from "../routes/elb/actions";
import { ICONS } from "./clients";

const TAG = AddTags.Tags.item?.fields ?? {};

/** A resource's tags, with add and remove. */
export function TagsSection({ arn, tags, testId }: { arn: string; tags: { Key?: string; Value?: string }[]; testId: string }) {
  return (
    <Section
      title="Tags"
      count={tags.length}
      plain
      actions={
        <Sheet title="Add tag" label="Add tag" testId={testId}>
          <ActionForm action={addTag.bind(null, arn)} submit="Add tag" testId={testId}>
            <div className="form-row">
              <Field label="Key" rule={TAG.Key}>
                <input name="key" required />
              </Field>
              <Field label="Value" rule={TAG.Value}>
                <input name="value" />
              </Field>
            </div>
          </ActionForm>
        </Sheet>
      }
    >
      <List
        label="Tags"
        empty={<Empty icon={ICONS.elb} />}
        rows={tags.map((t) => ({
          key: t.Key!,
          icon: <Tag size={16} />,
          title: t.Key,
          subtitle: t.Value,
          actions: <ActionForm action={removeTag.bind(null, arn, t.Key!)} submit={`Remove tag ${t.Key}`} icon={<X size={15} />} tone="danger" />,
        }))}
      />
    </Section>
  );
}


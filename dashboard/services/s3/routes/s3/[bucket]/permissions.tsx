import { GetBucketCorsCommand, GetBucketOwnershipControlsCommand, GetBucketPolicyCommand, GetBucketPolicyStatusCommand, GetPublicAccessBlockCommand } from "@aws-sdk/client-s3";
import { load } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, ErrorNotice, Facts, Field, Pill, Section, Sheet, Status, type FormAction } from "@mws-dashboard/ui";
import { Globe, Pencil, ShieldCheck } from "lucide-react";

import { optional, s3 } from "../../../lib/s3";
import { saveCors, saveOwnership, savePolicy, savePublicAccessBlock } from "../actions";

export const BPA_SETTINGS = [
  ["BlockPublicAcls", "Block new public ACLs"],
  ["IgnorePublicAcls", "Ignore public ACLs"],
  ["BlockPublicPolicy", "Block new public bucket and access point policies"],
  ["RestrictPublicBuckets", "Restrict public bucket and access point policies"],
] as const;

export type Bpa = Partial<Record<(typeof BPA_SETTINGS)[number][0], boolean>>;

/** "On" when all four are on, "Off" when none, else how many. */
export function bpaSummary(c: Bpa | undefined) {
  const on = BPA_SETTINGS.filter(([k]) => c?.[k]).length;
  return on === 4 ? <Status tone="good">All blocked</Status> : on === 0 ? <Status tone="warn">Off</Status> : <Status tone="warn">{`${on} of 4 on`}</Status>;
}

export function BpaForm({ action, current, testId }: { action: FormAction; current: Bpa | undefined; testId: string }) {
  return (
    <ActionForm action={action} submit="Save" testId={testId}>
      {BPA_SETTINGS.map(([k, label]) => (
        <label key={k} className="check">
          <input type="checkbox" name={k} defaultChecked={current ? !!current[k] : true} /> {label}
        </label>
      ))}
    </ActionForm>
  );
}

const CORS_TEMPLATE = [{ AllowedMethods: ["GET", "HEAD"], AllowedOrigins: ["*"], AllowedHeaders: ["*"], ExposeHeaders: ["ETag"], MaxAgeSeconds: 3000 }];

export async function Permissions({ bucket }: { bucket: string }) {
  const client = await s3();
  const data = await load(async () => {
    const [bpa, policy, status, ownership, cors] = await Promise.all([
      load(() => optional(() => client.send(new GetPublicAccessBlockCommand({ Bucket: bucket })))),
      optional(() => client.send(new GetBucketPolicyCommand({ Bucket: bucket }))),
      load(() => optional(() => client.send(new GetBucketPolicyStatusCommand({ Bucket: bucket })))),
      load(() => optional(() => client.send(new GetBucketOwnershipControlsCommand({ Bucket: bucket })))),
      load(() => optional(() => client.send(new GetBucketCorsCommand({ Bucket: bucket })))),
    ]);
    return { bpa, policy, status, ownership, cors };
  });
  if (!data.ok) return <ErrorNotice error={data.error} />;
  const { bpa, policy, status, ownership, cors } = data.value;
  const block = bpa.ok ? bpa.value?.PublicAccessBlockConfiguration : undefined;
  const isPublic = status.ok && status.value?.PolicyStatus?.IsPublic;
  const owner = ownership.ok ? ownership.value?.OwnershipControls?.Rules?.[0]?.ObjectOwnership : undefined;
  const rules = cors.ok ? (cors.value?.CORSRules ?? []) : [];
  return (
    <>
      <Section
        title="Block public access (bucket settings)"
        icon={<ShieldCheck size={16} aria-hidden />}
        actions={
          <Sheet title="Block public access" label="Edit Block Public Access" icon={<Pencil size={15} aria-hidden />} testId="edit-bucket-bpa">
            <BpaForm action={savePublicAccessBlock.bind(null, bucket)} current={bpa.ok ? (block ?? {}) : undefined} testId="edit-bucket-bpa" />
          </Sheet>
        }
      >
        {!bpa.ok ? (
          <ErrorNotice error={bpa.error} />
        ) : (
          <Facts items={[["Block all public access", bpaSummary(block)], ...BPA_SETTINGS.filter(([k]) => block && !block[k]).map(([, label]) => [label, "Off"] as [string, string])]} />
        )}
      </Section>
      <Section
        title="Bucket policy"
        actions={
          <Sheet title="Bucket policy" label="Edit policy" icon={<Pencil size={15} aria-hidden />} testId="edit-policy">
            <ActionForm action={savePolicy.bind(null, bucket)} submit="Save" testId="edit-policy">
              <Field label="Policy JSON" hint="Empty removes the policy" format="policy">
                <textarea name="policy" rows={14} defaultValue={policy?.Policy ? JSON.stringify(JSON.parse(policy.Policy), null, 2) : ""} />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {isPublic && (
          <p>
            <Pill tone="bad" icon={<Globe size={12} aria-hidden />}>
              Public
            </Pill>
          </p>
        )}
        {policy?.Policy ? <CodeBlock value={policy.Policy} label="Bucket policy" /> : <span className="muted">None</span>}
      </Section>
      <Section
        title="Object Ownership"
        actions={
          <Sheet title="Object Ownership" label="Edit Object Ownership" icon={<Pencil size={15} aria-hidden />} testId="edit-ownership">
            <ActionForm action={saveOwnership.bind(null, bucket)} submit="Save" testId="edit-ownership">
              <Field label="Object Ownership">
                <select name="ownership" defaultValue={owner ?? "BucketOwnerEnforced"}>
                  <option value="BucketOwnerEnforced">Bucket owner enforced (ACLs disabled)</option>
                  <option value="BucketOwnerPreferred">Bucket owner preferred</option>
                  <option value="ObjectWriter">Object writer</option>
                </select>
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {!ownership.ok ? (
          <ErrorNotice error={ownership.error} />
        ) : (
          <Facts items={[["Object Ownership", owner ?? "Object writer (no controls)"], ["ACLs", owner === "BucketOwnerEnforced" ? "Disabled" : "Enabled"]]} />
        )}
      </Section>
      <Section
        title="Cross-origin resource sharing (CORS)"
        count={rules.length}
        actions={
          <Sheet title="CORS" label="Edit CORS" icon={<Pencil size={15} aria-hidden />} testId="edit-cors">
            <ActionForm action={saveCors.bind(null, bucket)} submit="Save" testId="edit-cors">
              <Field label="CORS rules (JSON)" format="json" hint="Empty removes the configuration">
                <textarea name="cors" rows={14} defaultValue={JSON.stringify(rules.length ? rules : CORS_TEMPLATE, null, 2)} />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {!cors.ok ? <ErrorNotice error={cors.error} /> : rules.length ? <CodeBlock value={JSON.stringify(rules)} label="CORS rules" /> : <span className="muted">None</span>}
      </Section>
    </>
  );
}

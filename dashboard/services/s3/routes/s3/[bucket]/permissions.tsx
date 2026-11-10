import { GetBucketCorsCommand, GetBucketOwnershipControlsCommand, GetBucketPolicyCommand, GetBucketPolicyStatusCommand, GetPublicAccessBlockCommand } from "@aws-sdk/client-s3";
import { load } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, ErrorNotice, Facts, Field, Pill, Section, Sheet, Status, type FormAction } from "@mws-dashboard/ui";
import { FileJson, Globe, Pencil, ShieldCheck, Upload, Users } from "lucide-react";

import { account, optional, s3 } from "../../../lib/s3";
import { saveCors, saveOwnership, savePolicy, savePublicAccessBlock } from "../actions";
import { TemplateForm, type Template } from "../template-form.tsx";

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

const json = (v: unknown) => JSON.stringify(v, null, 2);
const ICON = { size: 26, strokeWidth: 1.5, "aria-hidden": true } as const;

/** Bucket policies people usually start from. */
function policyTemplates(bucket: string, account: string, current: string | undefined): Template[] {
  const arn = `arn:aws:s3:::${bucket}`;
  const doc = (Statement: object[]) => json({ Version: "2012-10-17", Statement });
  return [
    ...(current ? [{ id: "current", label: "Current", title: "The saved policy", icon: <FileJson {...ICON} />, text: json(JSON.parse(current)) }] : []),
    { id: "https", label: "HTTPS only", title: "Deny requests that do not use TLS", icon: <ShieldCheck {...ICON} />, text: doc([{ Sid: "DenyInsecureTransport", Effect: "Deny", Principal: "*", Action: "s3:*", Resource: [arn, `${arn}/*`], Condition: { Bool: { "aws:SecureTransport": "false" } } }]) },
    { id: "public-read", label: "Public read", title: "Anyone may read objects (Block Public Access must allow it)", icon: <Globe {...ICON} />, text: doc([{ Sid: "PublicRead", Effect: "Allow", Principal: "*", Action: "s3:GetObject", Resource: `${arn}/*` }]) },
    {
      id: "cloudfront",
      label: "CloudFront",
      title: "Let a CloudFront distribution read through origin access control",
      icon: "service/AmazonCloudFront",
      text: doc([{ Sid: "AllowCloudFrontServicePrincipal", Effect: "Allow", Principal: { Service: "cloudfront.amazonaws.com" }, Action: "s3:GetObject", Resource: `${arn}/*`, Condition: { StringEquals: { "AWS:SourceArn": `arn:aws:cloudfront::${account}:distribution/EDFDVBD6EXAMPLE` } } }]),
    },
    { id: "logs", label: "Access logs", title: "Let S3 server access logging write here", icon: "resource/AmazonCloudWatchLogs", text: doc([{ Sid: "S3ServerAccessLogs", Effect: "Allow", Principal: { Service: "logging.s3.amazonaws.com" }, Action: "s3:PutObject", Resource: `${arn}/*`, Condition: { StringEquals: { "aws:SourceAccount": account } } }]) },
    { id: "account", label: "Other account", title: "Let another account list and read", icon: <Users {...ICON} />, text: doc([{ Sid: "CrossAccountRead", Effect: "Allow", Principal: { AWS: "arn:aws:iam::111122223333:root" }, Action: ["s3:GetObject", "s3:ListBucket"], Resource: [arn, `${arn}/*`] }]) },
  ];
}

/** CORS configurations people usually start from. */
function corsTemplates(current: object[]): Template[] {
  return [
    ...(current.length ? [{ id: "current", label: "Current", title: "The saved rules", icon: <FileJson {...ICON} />, text: json(current) }] : []),
    { id: "read", label: "Read anywhere", title: "GET and HEAD from any origin", icon: <Globe {...ICON} />, text: json([{ AllowedMethods: ["GET", "HEAD"], AllowedOrigins: ["*"], AllowedHeaders: ["*"], ExposeHeaders: ["ETag"], MaxAgeSeconds: 3000 }]) },
    { id: "upload", label: "Browser uploads", title: "PUT and POST from your web app (presigned uploads)", icon: <Upload {...ICON} />, text: json([{ AllowedMethods: ["GET", "PUT", "POST", "HEAD"], AllowedOrigins: ["http://localhost:3000"], AllowedHeaders: ["*"], ExposeHeaders: ["ETag"], MaxAgeSeconds: 3000 }]) },
  ];
}

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
  const me = await account().catch(() => "123456789012");
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
            <TemplateForm action={savePolicy.bind(null, bucket)} testId="edit-policy" name="policy" label="Policy JSON" hint="Empty removes the policy" format="policy" templates={policyTemplates(bucket, me, policy?.Policy)} />
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
            <TemplateForm action={saveCors.bind(null, bucket)} testId="edit-cors" name="cors" label="CORS rules (JSON)" hint="Empty removes the configuration" format="json" templates={corsTemplates(rules)} />
          </Sheet>
        }
      >
        {!cors.ok ? <ErrorNotice error={cors.error} /> : rules.length ? <CodeBlock value={JSON.stringify(rules)} label="CORS rules" /> : <span className="muted">None</span>}
      </Section>
    </>
  );
}

import { ListAccessPointsCommand } from "@aws-sdk/client-s3-control";
import { all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Pill, Sheet, type Rule } from "@mws-dashboard/ui";
import { CreateAccessPoint } from "@mws-dashboard/ui/model/s3control";
import { Trash2 } from "lucide-react";

import { CONTROL_ICONS, accessPointHref, account, control } from "../../lib/s3";
import { createAccessPoint, deleteAccessPoint } from "./control-actions";
import { BPA_SETTINGS } from "./[bucket]/permissions";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

// The model allows 3-255; S3 asks for 3-50 lowercase letters, digits and
// hyphens, starting and ending with a letter or digit.
const NAME: Rule = { ...CreateAccessPoint.Name, maxLength: 50, pattern: "^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$", hint: "Lowercase letters, digits and -", generate: "name" };

export async function accessPoints(bucket?: string) {
  const AccountId = await account();
  const client = await control();
  return all(
    (NextToken) => client.send(new ListAccessPointsCommand({ AccountId, Bucket: bucket, NextToken })),
    (r) => r.AccessPointList,
    (r) => r.NextToken,
  );
}

export function CreateAccessPointSheet({ bucket, buckets, taken }: { bucket?: string; buckets?: string[]; taken: string[] }) {
  return (
    <Sheet title="Create access point" label="Create access point" icon={bucket ? <AwsIcon icon={CONTROL_ICONS.accessPoint} size={16} /> : undefined} testId="create-access-point">
      <ActionForm action={createAccessPoint.bind(null, bucket ?? null)} submit="Create" testId="create-access-point">
        <Field label="Name" rule={NAME} taken={taken} unique>
          <input name="name" required autoFocus />
        </Field>
        {!bucket && (
          <Field label="Bucket" rule={CreateAccessPoint.Bucket}>
            <select name="bucket" required>
              {(buckets ?? []).map((b) => (
                <option key={b}>{b}</option>
              ))}
            </select>
          </Field>
        )}
        <div className="form-row">
          <Field label="Network origin">
            <select name="network" defaultValue="internet">
              <option value="internet">Internet</option>
              <option value="vpc">Virtual private cloud (VPC)</option>
            </select>
          </Field>
          <Field label="VPC ID" rule={{ pattern: "^vpc-[0-9a-f]+$", hint: "Only for a VPC origin" }} member="VpcConfiguration.VpcId">
            <ResourcePicker kind="vpc" name="vpc" />
          </Field>
        </div>
        <fieldset className="field">
          <legend className="field-label">Block Public Access</legend>
          {BPA_SETTINGS.map(([k, label]) => (
            <label key={k} className="check">
              <input type="checkbox" name={k} defaultChecked /> {label}
            </label>
          ))}
        </fieldset>
      </ActionForm>
    </Sheet>
  );
}

export async function AccessPointList({ bucket }: { bucket?: string }) {
  const points = await load(() => accessPoints(bucket));
  if (!points.ok) return <ErrorNotice error={points.error} />;
  return (
    <List
      label="Access points"
      empty={<Empty icon={CONTROL_ICONS.accessPoint} />}
      rows={points.value.map((p) => ({
        key: p.AccessPointArn ?? p.Name!,
        icon: <AwsIcon icon={p.NetworkOrigin === "VPC" ? CONTROL_ICONS.vpcAccessPoint : CONTROL_ICONS.accessPoint} size={24} />,
        title: p.Name,
        subtitle: bucket ? p.Alias : `${p.Bucket} · ${p.Alias ?? ""}`,
        href: accessPointHref(p.Bucket!, p.Name!),
        meta: <Pill tone={p.NetworkOrigin === "VPC" ? "neutral" : "info"}>{p.NetworkOrigin === "VPC" ? `VPC ${p.VpcConfiguration?.VpcId ?? ""}` : "Internet"}</Pill>,
        actions: <ActionForm action={deleteAccessPoint.bind(null, p.Name!, null)} submit={`Delete access point ${p.Name}`} icon={<Trash2 size={15} aria-hidden />} tone="danger" confirm={`Delete access point ${p.Name}? Applications using it lose access.`} />,
      }))}
    />
  );
}

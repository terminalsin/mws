import "server-only";

import type { Instance } from "@aws-sdk/client-ec2";
import { ActionForm, Field, Section, Sheet } from "@mws-dashboard/ui";
import { Camera, Copy, FileCode, KeyRound, LayoutTemplate, ShieldCheck, SlidersHorizontal } from "lucide-react";

import { changeGroups, changeInstanceProfile, changeInstanceType, changeMetadata, changeProtection, changeUserData } from "../../routes/ec2/actions";
import { snapshotInstance } from "../../routes/ec2/ebs";
import { createImage } from "../../routes/ec2/images";
import { templateFromInstance } from "../../routes/ec2/templates";
import { nameTag } from "../clients";
import { HOP_LIMIT, IMAGE_DESCRIPTION, IMAGE_NAME, INSTANCE_TYPE, SNAPSHOT_DESCRIPTION, TEMPLATE_NAME } from "../rules";

export interface InstanceAttributes {
  termination?: boolean;
  stop?: boolean;
  shutdown?: string;
  userData?: string;
}

const TYPES = ["t3.nano", "t3.micro", "t3.small", "t3.medium", "t3.large", "t4g.micro", "t4g.small", "m7i.large", "m7g.large", "c7g.large", "r7g.large"];

/** "Instance settings": type (stopped only), protection, shutdown behavior and user data (stopped only). */
export function SettingsSheet({ instance, attributes }: { instance: Instance; attributes: InstanceAttributes }) {
  const id = instance.InstanceId!;
  const stopped = instance.State?.Name === "stopped";
  return (
    <Sheet title="Instance settings" label="Instance settings" icon={<SlidersHorizontal size={16} />} testId="instance-settings">
      <Section title="Instance type">
        {stopped ? (
          <ActionForm action={changeInstanceType.bind(null, id)} submit="Change type" testId="change-type">
            <Field label="Instance type" rule={INSTANCE_TYPE} member="InstanceType">
              <input name="type" defaultValue={instance.InstanceType} list="settings-types" required />
            </Field>
            <datalist id="settings-types">
              {TYPES.map((t) => (
                <option key={t} value={t} />
              ))}
            </datalist>
          </ActionForm>
        ) : (
          <span className="muted">Stop the instance to change its type</span>
        )}
      </Section>
      <Section title="Protection">
        <ActionForm action={changeProtection.bind(null, id)} submit="Save" testId="change-protection">
          <label className="check">
            <input type="checkbox" name="termination" defaultChecked={attributes.termination} /> Termination protection
          </label>
          <label className="check">
            <input type="checkbox" name="stop" defaultChecked={attributes.stop} /> Stop protection
          </label>
          <Field label="Shutdown behavior">
            <select name="shutdown" defaultValue={attributes.shutdown ?? "stop"}>
              <option value="stop">Stop</option>
              <option value="terminate">Terminate</option>
            </select>
          </Field>
        </ActionForm>
      </Section>
      <Section title="User data">
        {stopped ? (
          <ActionForm action={changeUserData.bind(null, id)} submit="Save user data" testId="change-user-data">
            <textarea name="userData" rows={6} aria-label="User data" defaultValue={attributes.userData} className="code-editor" />
          </ActionForm>
        ) : (
          <span className="muted">Stop the instance to edit its user data</span>
        )}
      </Section>
    </Sheet>
  );
}

export function MetadataSheet({ instance }: { instance: Instance }) {
  const m = instance.MetadataOptions ?? {};
  return (
    <Sheet title="Instance metadata options" label="Modify instance metadata options" icon={<FileCode size={16} />} testId="metadata-options">
      <ActionForm action={changeMetadata.bind(null, instance.InstanceId!)} submit="Save" testId="metadata-options">
        <Field label="Metadata service">
          <select name="endpoint" defaultValue={m.HttpEndpoint ?? "enabled"}>
            <option value="enabled">Enabled</option>
            <option value="disabled">Disabled</option>
          </select>
        </Field>
        <Field label="IMDSv2" member="HttpTokens">
          <select name="tokens" defaultValue={m.HttpTokens ?? "required"}>
            <option value="required">Required</option>
            <option value="optional">Optional</option>
          </select>
        </Field>
        <Field label="Hop limit" rule={HOP_LIMIT} member="HttpPutResponseHopLimit">
          <input name="hopLimit" type="number" defaultValue={m.HttpPutResponseHopLimit ?? 2} />
        </Field>
        <Field label="Tags in metadata">
          <select name="tags" defaultValue={m.InstanceMetadataTags ?? "disabled"}>
            <option value="disabled">Off</option>
            <option value="enabled">On</option>
          </select>
        </Field>
      </ActionForm>
    </Sheet>
  );
}

export function RoleSheet({ instance, profiles }: { instance: Instance; profiles: { name: string; arn: string }[] }) {
  const current = instance.IamInstanceProfile?.Arn?.split("/").pop() ?? "";
  return (
    <Sheet title="Modify IAM role" label="Modify IAM role" icon={<KeyRound size={16} />} testId="modify-role">
      <ActionForm action={changeInstanceProfile.bind(null, instance.InstanceId!)} submit="Update" testId="modify-role">
        <Field label="IAM instance profile" member="IamInstanceProfile">
          <select name="iamProfile" defaultValue={current}>
            <option value="">No IAM role</option>
            {profiles.map((p) => (
              <option key={p.arn} value={p.name}>
                {p.name}
              </option>
            ))}
          </select>
        </Field>
      </ActionForm>
    </Sheet>
  );
}

export function GroupsSheet({ instance, groups }: { instance: Instance; groups: { id: string; name: string; vpc: string }[] }) {
  const attached = new Set(instance.SecurityGroups?.map((g) => g.GroupId));
  const mine = groups.filter((g) => g.vpc === instance.VpcId);
  return (
    <Sheet title="Change security groups" label="Change security groups" icon={<ShieldCheck size={16} />} testId="change-groups">
      <ActionForm action={changeGroups.bind(null, instance.InstanceId!)} submit="Save" testId="change-groups">
        <fieldset className="checks">
          <legend>Security groups</legend>
          {mine.map((g) => (
            <label key={g.id} className="check">
              <input type="checkbox" name="securityGroups" value={g.id} defaultChecked={attached.has(g.id)} /> {g.name}
            </label>
          ))}
        </fieldset>
      </ActionForm>
    </Sheet>
  );
}

export function CreateImageSheet({ instance }: { instance: Instance }) {
  return (
    <Sheet title="Create image" label="Create image" icon={<Copy size={16} />} testId="create-image">
      <ActionForm action={createImage.bind(null, instance.InstanceId!)} submit="Create image" testId="create-image">
        <Field label="Image name" rule={IMAGE_NAME} member="Name" unique>
          <input name="name" required autoFocus defaultValue={nameTag(instance) ? `${nameTag(instance)}-image` : undefined} />
        </Field>
        <Field label="Description" rule={IMAGE_DESCRIPTION} member="Description">
          <input name="description" />
        </Field>
        <label className="check">
          <input type="checkbox" name="noReboot" /> No reboot
        </label>
      </ActionForm>
    </Sheet>
  );
}

export function TemplateFromInstanceSheet({ instance, taken }: { instance: Instance; taken: string[] }) {
  return (
    <Sheet title="Create template from instance" label="Create template from instance" icon={<LayoutTemplate size={16} />} testId="template-from-instance">
      <ActionForm action={templateFromInstance.bind(null, instance.InstanceId!)} submit="Create" testId="template-from-instance">
        <Field label="Template name" rule={TEMPLATE_NAME} member="LaunchTemplateName" taken={taken} unique>
          <input name="name" required autoFocus defaultValue={nameTag(instance) ? `${nameTag(instance)}-template`.replace(/[^a-zA-Z0-9().\-/_]/g, "-") : undefined} />
        </Field>
      </ActionForm>
    </Sheet>
  );
}

export function SnapshotInstanceSheet({ instance }: { instance: Instance }) {
  return (
    <Sheet title="Snapshot volumes" label="Create snapshots of all volumes" icon={<Camera size={16} />} testId="snapshot-instance">
      <ActionForm action={snapshotInstance.bind(null, instance.InstanceId!)} submit="Create snapshots" testId="snapshot-instance">
        <Field label="Description" rule={SNAPSHOT_DESCRIPTION} member="Description">
          <input name="description" defaultValue={`From ${instance.InstanceId}`} />
        </Field>
        <label className="check">
          <input type="checkbox" name="excludeRoot" /> Exclude root volume
        </label>
      </ActionForm>
    </Sheet>
  );
}


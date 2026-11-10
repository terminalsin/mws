import { GetInstanceProfileCommand, ListRolesCommand } from "@aws-sdk/client-iam";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Facts, Field, List, Page, Section, Sheet, Tags } from "@mws-dashboard/ui";
import { Tag, Trash2, Unlink, Plus } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, iam } from "../../../../lib/clients";
import { RULES } from "../../../../lib/rules";
import { addRoleToProfile, deleteInstanceProfile, removeRoleFromProfile, saveTags } from "../../actions";

type Props = { params: Promise<{ name: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: decodeURIComponent((await params).name) };
}

/** An instance profile: the container EC2 passes a role to instances in. */
export default async function InstanceProfile({ params }: Props) {
  const name = decodeURIComponent((await params).name);
  const back = { href: "/iam?tab=roles", label: "Roles" };
  const data = await load(async () => {
    const client = await iam();
    const [profile, roles] = await Promise.all([
      client.send(new GetInstanceProfileCommand({ InstanceProfileName: name })).then((r) => r.InstanceProfile!),
      all((Marker) => client.send(new ListRolesCommand({ Marker })), (r) => r.Roles, (r) => (r.IsTruncated ? r.Marker : undefined)),
    ]);
    return { profile, roles };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.role} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { profile, roles } = data.value;
  const tags = profile.Tags ?? [];
  const inProfile = profile.Roles ?? [];
  return (
    <Page
      title={name}
      icon={ICONS.role}
      back={back}
      subtitle={profile.Arn}
      actions={
        <>
          <Sheet title="Tags" label="Edit tags" icon={<Tag size={16} />} testId="edit-tags">
            <ActionForm action={saveTags.bind(null, "instance-profile", name, tags.map((t) => t.Key!))} submit="Save" testId="edit-tags">
              <Field label="Tags" format="tags">
                <textarea name="tags" rows={6} placeholder="team=payments" defaultValue={tags.map((t) => `${t.Key}=${t.Value}`).join("\n")} />
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm
            action={deleteInstanceProfile.bind(null, name)}
            submit="Delete instance profile"
            icon={<Trash2 size={16} />}
            tone="danger"
            confirm={`Delete ${name}? Instances using it lose its role.`}
            testId="delete-instance-profile"
          />
        </>
      }
    >
      <Facts
        items={[
          profile.Path !== "/" && ["Path", <code key="p">{profile.Path}</code>],
          ["Created", ago(profile.CreateDate)],
          tags.length > 0 && ["Tags", <Tags key="t" tags={tags} />],
        ]}
      />
      <Section
        title="Role"
        count={inProfile.length}
        plain
        actions={
          inProfile.length === 0 && (
            <Sheet title="Add role" label="Add role" icon={<Plus size={16} />} testId="add-profile-role">
              <ActionForm action={addRoleToProfile.bind(null, name)} submit="Add" testId="add-profile-role">
                <Field label="Role" rule={RULES.roleName}>
                  <select name="role" required>
                    {roles
                      .filter((r) => !r.Path?.startsWith("/aws-service-role/"))
                      .map((r) => (
                        <option key={r.RoleId}>{r.RoleName}</option>
                      ))}
                  </select>
                </Field>
              </ActionForm>
            </Sheet>
          )
        }
      >
        <List
          label="Roles"
          empty={<Empty icon={ICONS.role} />}
          rows={inProfile.map((r) => ({
            key: r.RoleId!,
            icon: <AwsIcon icon={ICONS.role} size={22} />,
            title: r.RoleName,
            subtitle: r.Arn,
            href: `/iam/roles/${encodeURIComponent(r.RoleName!)}`,
            actions: <ActionForm action={removeRoleFromProfile.bind(null, name, r.RoleName!)} submit={`Remove ${r.RoleName}`} icon={<Unlink size={15} />} confirm={`Remove ${r.RoleName} from ${name}?`} />,
          }))}
        />
      </Section>
    </Page>
  );
}

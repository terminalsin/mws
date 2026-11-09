import { DescribeAutoScalingGroupsCommand } from "@aws-sdk/client-auto-scaling";
import { ago, collect, load } from "@mws-dashboard/aws";
import { ActionForm, AutoPick, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Status } from "@mws-dashboard/ui";
import { FileStack, HeartPulse } from "lucide-react";
import type { Metadata } from "next";

import { Capacity } from "../../lib/capacity";
import { autoscaling, ICONS } from "../../lib/clients";
import { images, launchTemplates } from "../../lib/network";
import { createGroup, createLaunchTemplate } from "./actions";

export const metadata: Metadata = { title: "Auto Scaling groups" };

export default async function Groups() {
  const client = await autoscaling();
  const [groups, templates, amis] = await Promise.all([
    load(() => collect((NextToken) => client.send(new DescribeAutoScalingGroupsCommand({ NextToken })), (r) => r.AutoScalingGroups, (r) => r.NextToken)),
    load(launchTemplates),
    load(images),
  ]);
  const templateSheet = (
    <Sheet title="Create launch template" label="Create launch template" icon={<FileStack size={15} />} testId="create-launch-template">
      <ActionForm action={createLaunchTemplate} submit="Create launch template" testId="create-launch-template">
        <Field label="Name">
          <input name="name" required autoFocus />
        </Field>
        <Field label="Image">
          <select name="image">
            {(amis.ok ? amis.value : []).map((i) => (
              <option key={i.ImageId} value={i.ImageId}>
                {i.Name ?? i.ImageId}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Instance type">
          <input name="type" defaultValue="t3.micro" />
        </Field>
      </ActionForm>
    </Sheet>
  );
  const groupSheet = (
    <Sheet title="Create Auto Scaling group" label="Create Auto Scaling group" testId="create-group">
      <ActionForm action={createGroup} submit="Create Auto Scaling group" testId="create-group">
        <Field label="Name">
          <input name="name" required autoFocus />
        </Field>
        <AutoPick
          name="template"
          label="Launch template"
          creates={`<group>-template · ${(amis.ok && amis.value[0]?.Name) || "latest image"} · t3.micro`}
          options={templates.ok ? templates.value.map((t) => ({ value: t.LaunchTemplateName!, label: t.LaunchTemplateName! })) : []}
          testId="launch-template"
        />
        <div className="form-row">
          <Field label="Min">
            <input name="min" type="number" min={0} defaultValue={0} />
          </Field>
          <Field label="Desired">
            <input name="desired" type="number" min={0} defaultValue={1} />
          </Field>
          <Field label="Max">
            <input name="max" type="number" min={0} defaultValue={2} />
          </Field>
        </div>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page
      title="Auto Scaling groups"
      actions={
        <>
          {templateSheet}
          {groupSheet}
        </>
      }
    >
      {groups.ok ? (
        <Section plain>
          <List
            label="Auto Scaling groups"
            empty={<Empty icon={ICONS.autoscaling} action={groupSheet || templateSheet} />}
            rows={groups.value.map((g) => {
              const instances = g.Instances ?? [];
              const running = instances.filter((i) => i.LifecycleState === "InService").length;
              const unhealthy = instances.filter((i) => i.HealthStatus === "Unhealthy").length;
              const lt = g.LaunchTemplate ?? g.MixedInstancesPolicy?.LaunchTemplate?.LaunchTemplateSpecification;
              return {
                key: g.AutoScalingGroupARN!,
                icon: <AwsIcon icon={ICONS.asg} size={22} />,
                title: g.AutoScalingGroupName,
                subtitle: lt?.LaunchTemplateName ?? lt?.LaunchTemplateId ?? g.LaunchConfigurationName,
                href: `/autoscaling/group?name=${encodeURIComponent(g.AutoScalingGroupName!)}`,
                meta: (
                  <>
                    {unhealthy > 0 && (
                      <Pill tone="bad" icon={<HeartPulse size={11} />}>
                        {unhealthy}
                      </Pill>
                    )}
                    {g.Status && <Status tone="warn">{g.Status.toLowerCase()}</Status>}
                    <Capacity running={running} desired={g.DesiredCapacity ?? 0} min={g.MinSize ?? 0} max={g.MaxSize ?? 0} />
                    <span>{ago(g.CreatedTime)}</span>
                  </>
                ),
              };
            })}
          />
        </Section>
      ) : (
        <ErrorNotice error={groups.error} />
      )}
    </Page>
  );
}

"use server";

import {
  CreateAutoScalingGroupCommand,
  DeleteAutoScalingGroupCommand,
  DeletePolicyCommand,
  PutScalingPolicyCommand,
  SetDesiredCapacityCommand,
  UpdateAutoScalingGroupCommand,
} from "@aws-sdk/client-auto-scaling";
import { CreateLaunchTemplateCommand, type _InstanceType } from "@aws-sdk/client-ec2";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { wantsAuto } from "@mws-dashboard/aws/auto";
import { redirect } from "next/navigation";

import { autoscaling, ec2 } from "../../lib/clients";
import { sizeIssue } from "../../lib/issues";
import { defaultSubnets, images } from "../../lib/network";

const int = (form: FormData, name: string) => {
  const v = text(form, name);
  return v === "" ? undefined : Number(v);
};

/** Form fields by the API member they fill. */
const SIZE_FIELDS = {
  AutoScalingGroupName: "name",
  MinSize: "min",
  MaxSize: "max",
  DesiredCapacity: "desired",
  VPCZoneIdentifier: "subnet",
  HealthCheckType: "health",
  HealthCheckGracePeriod: "grace",
  Tags: "tags",
};

/** `key=value` lines as pairs. */
function tagLines(lines: string): [string, string][] {
  return lines
    .split(/\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const i = l.indexOf("=");
      return (i < 0 ? [l, ""] : [l.slice(0, i).trim(), l.slice(i + 1).trim()]) as [string, string];
    });
}

export async function createLaunchTemplate(_: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ec2()).send(
      new CreateLaunchTemplateCommand({
        LaunchTemplateName: required(form, "name", "Name"),
        LaunchTemplateData: { ImageId: required(form, "image", "Image"), InstanceType: (text(form, "type") || "t3.micro") as _InstanceType },
      }),
    );
    return "Created";
  }, {
    revalidate: ["/autoscaling"],
    fields: {
      LaunchTemplateName: "name",
      "LaunchTemplateData.ImageId": "image",
      "LaunchTemplateData.InstanceType": "type",
      "InvalidLaunchTemplateName.MalformedException": "name",
      "InvalidAMIID.Malformed": "image",
      "InvalidAMIID.NotFound": "image",
    },
  });
}

export async function createGroup(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    const picked = form.getAll("subnet").map(String).filter(Boolean);
    if (text(form, "vpc") && picked.length === 0) throw new FieldError("subnet", "Pick at least one subnet", "required");
    const subnets = picked.length ? picked : await defaultSubnets();
    const grace = int(form, "grace");
    let template = text(form, "template");
    if (wantsAuto(form, "template")) {
      const image = (await images())[0];
      if (!image?.ImageId) throw new Error("No image to launch: register an AMI first");
      template = `${name}-template`;
      await (await ec2()).send(new CreateLaunchTemplateCommand({ LaunchTemplateName: template, LaunchTemplateData: { ImageId: image.ImageId, InstanceType: "t3.micro" } }));
    }
    try {
      await (await autoscaling()).send(
        new CreateAutoScalingGroupCommand({
          AutoScalingGroupName: name,
          LaunchTemplate: { LaunchTemplateName: template, Version: "$Latest" },
          MinSize: int(form, "min") ?? 0,
          MaxSize: int(form, "max") ?? 1,
          DesiredCapacity: int(form, "desired"),
          VPCZoneIdentifier: subnets.join(","),
          TargetGroupARNs: form.getAll("tg").map(String).filter(Boolean),
          HealthCheckType: text(form, "health") || undefined,
          HealthCheckGracePeriod: grace,
          NewInstancesProtectedFromScaleIn: form.get("protect") === "on" || undefined,
          CapacityRebalance: form.get("rebalance") === "on" || undefined,
          Tags: tagLines(text(form, "tags")).map(([Key, Value]) => ({ Key, Value, PropagateAtLaunch: true })),
        }),
      );
    } catch (e) {
      const issue = sizeIssue(e);
      if (issue) return issue;
      throw e;
    }
    redirect(`/autoscaling/group?name=${encodeURIComponent(name)}`);
  }, { fields: SIZE_FIELDS });
}

export async function editCapacity(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    try {
      await (await autoscaling()).send(
        new UpdateAutoScalingGroupCommand({ AutoScalingGroupName: name, MinSize: int(form, "min"), MaxSize: int(form, "max"), DesiredCapacity: int(form, "desired") }),
      );
    } catch (e) {
      const issue = sizeIssue(e);
      if (issue) return issue;
      throw e;
    }
    return "Updated";
  }, { revalidate: ["/autoscaling/group", "/autoscaling"], fields: SIZE_FIELDS });
}

export async function scale(name: string, desired: number) {
  return act(async () => {
    await (await autoscaling()).send(new SetDesiredCapacityCommand({ AutoScalingGroupName: name, DesiredCapacity: desired }));
    return `Desired ${desired}`;
  }, "/autoscaling/group", "/autoscaling");
}

/** Step lines (`lower:upper=adjustment`) as StepAdjustments. */
function steps(lines: string) {
  return lines
    .split(/\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const m = /^(-?[\d.]*)\s*:\s*(-?[\d.]*)\s*=\s*(-?\d+)$/.exec(l);
      if (!m) throw new FieldError("steps", `Not lower:upper=adjustment: ${l}`, "pattern");
      return {
        MetricIntervalLowerBound: m[1] === "" ? undefined : Number(m[1]),
        MetricIntervalUpperBound: m[2] === "" ? undefined : Number(m[2]),
        ScalingAdjustment: Number(m[3]),
      };
    });
}

export async function addPolicy(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const PolicyName = required(form, "policy", "Policy name");
    const type = text(form, "type") || "TargetTrackingScaling";
    const AdjustmentType = text(form, "adjustment") || "ChangeInCapacity";
    const input =
      type === "TargetTrackingScaling"
        ? {
            TargetTrackingConfiguration: {
              PredefinedMetricSpecification: { PredefinedMetricType: (text(form, "metric") || "ASGAverageCPUUtilization") as "ASGAverageCPUUtilization" },
              TargetValue: Number(text(form, "target") || "50"),
              DisableScaleIn: form.get("disableScaleIn") === "on",
            },
          }
        : type === "StepScaling"
          ? { AdjustmentType, StepAdjustments: steps(text(form, "steps")) }
          : { AdjustmentType, ScalingAdjustment: Number(required(form, "amount", "Adjustment")), Cooldown: int(form, "cooldown") };
    await (await autoscaling()).send(new PutScalingPolicyCommand({ AutoScalingGroupName: name, PolicyName, PolicyType: type, ...input }));
    return "Added";
  }, {
    revalidate: ["/autoscaling/group"],
    fields: { PolicyName: "policy", "TargetTrackingConfiguration.TargetValue": "target", ScalingAdjustment: "amount", StepAdjustments: "steps", Cooldown: "cooldown", AdjustmentType: "adjustment" },
  });
}

export async function deletePolicy(name: string, policy: string) {
  return act(async () => {
    await (await autoscaling()).send(new DeletePolicyCommand({ AutoScalingGroupName: name, PolicyName: policy }));
    return "Deleted";
  }, "/autoscaling/group");
}

export async function deleteGroup(name: string) {
  return act(async () => {
    await (await autoscaling()).send(new DeleteAutoScalingGroupCommand({ AutoScalingGroupName: name, ForceDelete: true }));
    redirect("/autoscaling");
  });
}

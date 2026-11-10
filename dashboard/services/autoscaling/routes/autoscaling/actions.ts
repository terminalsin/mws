"use server";

import {
  CreateAutoScalingGroupCommand,
  DeleteAutoScalingGroupCommand,
  DeletePolicyCommand,
  PutScalingPolicyCommand,
  SetDesiredCapacityCommand,
  TerminateInstanceInAutoScalingGroupCommand,
  UpdateAutoScalingGroupCommand,
  StartInstanceRefreshCommand,
} from "@aws-sdk/client-auto-scaling";
import { CreateLaunchTemplateCommand, type _InstanceType } from "@aws-sdk/client-ec2";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { wantsAuto } from "@mws-dashboard/aws/auto";
import { redirect } from "next/navigation";

import { autoscaling, ec2 } from "../../lib/clients";
import { defaultSubnets, images } from "../../lib/network";

const int = (form: FormData, name: string) => {
  const v = text(form, name);
  return v === "" ? undefined : Number(v);
};

export async function createLaunchTemplate(_: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ec2()).send(
      new CreateLaunchTemplateCommand({
        LaunchTemplateName: required(form, "name", "Name"),
        LaunchTemplateData: { ImageId: required(form, "image", "Image"), InstanceType: (text(form, "type") || "t3.micro") as _InstanceType },
      }),
    );
    return "Created";
  }, "/autoscaling");
}

export async function createGroup(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    const subnets = await defaultSubnets();
    let template = text(form, "template");
    if (wantsAuto(form, "template")) {
      const image = (await images())[0];
      if (!image?.ImageId) throw new Error("No image to launch: register an AMI first");
      template = `${name}-template`;
      await (await ec2()).send(new CreateLaunchTemplateCommand({ LaunchTemplateName: template, LaunchTemplateData: { ImageId: image.ImageId, InstanceType: "t3.micro" } }));
    }
    await (await autoscaling()).send(
      new CreateAutoScalingGroupCommand({
        AutoScalingGroupName: name,
        LaunchTemplate: { LaunchTemplateName: template, Version: "$Latest" },
        MinSize: int(form, "min") ?? 0,
        MaxSize: int(form, "max") ?? 1,
        DesiredCapacity: int(form, "desired"),
        VPCZoneIdentifier: subnets.join(","),
      }),
    );
    redirect(`/autoscaling/group?name=${encodeURIComponent(name)}`);
  });
}

export async function editCapacity(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await autoscaling()).send(
      new UpdateAutoScalingGroupCommand({ AutoScalingGroupName: name, MinSize: int(form, "min"), MaxSize: int(form, "max"), DesiredCapacity: int(form, "desired") }),
    );
    return "Updated";
  }, "/autoscaling/group", "/autoscaling");
}

export async function scale(name: string, desired: number) {
  return act(async () => {
    await (await autoscaling()).send(new SetDesiredCapacityCommand({ AutoScalingGroupName: name, DesiredCapacity: desired }));
    return `Desired ${desired}`;
  }, "/autoscaling/group", "/autoscaling");
}

export async function refresh(name: string) {
  return act(async () => {
    await (await autoscaling()).send(new StartInstanceRefreshCommand({ AutoScalingGroupName: name }));
    return "Refresh started";
  }, "/autoscaling/group");
}

export async function terminate(instanceId: string, decrement: boolean) {
  return act(async () => {
    await (await autoscaling()).send(new TerminateInstanceInAutoScalingGroupCommand({ InstanceId: instanceId, ShouldDecrementDesiredCapacity: decrement }));
    return "Terminating";
  }, "/autoscaling/group");
}

export async function addPolicy(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await autoscaling()).send(
      new PutScalingPolicyCommand({
        AutoScalingGroupName: name,
        PolicyName: required(form, "policy", "Policy name"),
        PolicyType: "TargetTrackingScaling",
        TargetTrackingConfiguration: {
          PredefinedMetricSpecification: { PredefinedMetricType: (text(form, "metric") || "ASGAverageCPUUtilization") as "ASGAverageCPUUtilization" },
          TargetValue: Number(text(form, "target") || "50"),
        },
      }),
    );
    return "Added";
  }, "/autoscaling/group");
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

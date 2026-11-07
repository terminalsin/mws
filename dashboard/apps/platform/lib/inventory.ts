import "server-only";

import { ListAppsCommand } from "@aws-sdk/client-amplify";
import { DescribeAutoScalingGroupsCommand } from "@aws-sdk/client-auto-scaling";
import { ListGuardrailsCommand } from "@aws-sdk/client-bedrock";
import { ListRepositoriesCommand } from "@aws-sdk/client-codeartifact";
import { ListImagePipelinesCommand } from "@aws-sdk/client-imagebuilder";
import { type InventoryItem } from "@mws-dashboard/aws";

import { amplify, autoscaling, bedrock, codeartifact, imagebuilder } from "./clients";
import { products as catalog } from "./marketplace";

const base = "/platform";

export async function guardrails(): Promise<InventoryItem[]> {
  const out = await (await bedrock()).send(new ListGuardrailsCommand({}));
  return (out.guardrails ?? []).map((g) => ({ service: "bedrock", type: "Guardrail", id: g.arn!, name: g.name!, href: `${base}/bedrock/guardrail?id=${g.id}` }));
}

export async function apps(): Promise<InventoryItem[]> {
  const out = await (await amplify()).send(new ListAppsCommand({ maxResults: 100 }));
  return (out.apps ?? []).map((a) => ({
    service: "amplify",
    type: "App",
    id: a.appArn!,
    name: a.name!,
    href: `${base}/amplify/app?id=${a.appId}`,
    detail: a.defaultDomain,
    tags: a.tags,
    signal: a.productionBranch?.status === "FAILED" ? { tone: "bad" as const, text: "Deploy failed" } : undefined,
  }));
}

export async function repositories(): Promise<InventoryItem[]> {
  const out = await (await codeartifact()).send(new ListRepositoriesCommand({}));
  return (out.repositories ?? []).map((r) => ({
    service: "codeartifact",
    type: "Package repository",
    id: r.arn!,
    name: r.name!,
    href: `${base}/codeartifact/repo?domain=${encodeURIComponent(r.domainName!)}&name=${encodeURIComponent(r.name!)}`,
    detail: r.domainName,
  }));
}

export async function pipelines(): Promise<InventoryItem[]> {
  const out = await (await imagebuilder()).send(new ListImagePipelinesCommand({}));
  return (out.imagePipelineList ?? []).map((p) => ({ service: "imagebuilder", type: "Image pipeline", id: p.arn!, name: p.name!, href: `${base}/imagebuilder`, tags: p.tags }));
}

export async function groups(): Promise<InventoryItem[]> {
  const out = await (await autoscaling()).send(new DescribeAutoScalingGroupsCommand({}));
  return (out.AutoScalingGroups ?? []).map((g) => {
    const running = (g.Instances ?? []).filter((i) => i.LifecycleState === "InService").length;
    const unhealthy = (g.Instances ?? []).filter((i) => i.HealthStatus === "Unhealthy").length;
    return {
      service: "autoscaling",
      type: "Auto Scaling group",
      id: g.AutoScalingGroupARN!,
      name: g.AutoScalingGroupName!,
      href: `${base}/autoscaling/group?name=${encodeURIComponent(g.AutoScalingGroupName!)}`,
      detail: `${running}/${g.DesiredCapacity}`,
      tags: Object.fromEntries((g.Tags ?? []).map((t) => [t.Key!, t.Value ?? ""])),
      signal: unhealthy ? { tone: "bad" as const, text: `${unhealthy} unhealthy` } : undefined,
    };
  });
}

export async function products(): Promise<InventoryItem[]> {
  return (await catalog()).map((p) => ({ service: "marketplace", type: "Product", id: p.productCode, name: p.title || p.productCode, href: `${base}/marketplace/product?code=${p.productCode}`, detail: p.productType }));
}

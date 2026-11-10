"use server";

import { CreateChallengeCommand, CreateConnectorCommand, DeleteChallengeCommand, DeleteConnectorCommand, TagResourceCommand, UntagResourceCommand } from "@aws-sdk/client-pca-connector-scep";
import { GetPolicyCommand, PutPolicyCommand } from "@aws-sdk/client-acm-pca";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { pca, scep } from "../../../lib/clients";

const PAGE = "/pca/connector";

const SID = "AllowPcaConnectorScep";

/** The connector issues as pca-connector-scep.amazonaws.com, so the CA's
 * policy (or a RAM share) must let that principal issue from this account;
 * otherwise the connector fails with PRIVATECA_ACCESS_DENIED. Adds that
 * statement to the CA's policy, keeping the rest. */
async function allowConnector(ca: string, account: string) {
  const c = await pca();
  const current = await c
    .send(new GetPolicyCommand({ ResourceArn: ca }))
    .then((r) => (r.Policy ? JSON.parse(r.Policy) : null))
    .catch((e: unknown) => {
      if (e instanceof Error && e.name === "ResourceNotFoundException" && /policy/i.test(e.message)) return null;
      throw e;
    });
  const doc = current ?? { Version: "2012-10-17", Statement: [] };
  const statements = (Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement]).filter((s: { Sid?: string }) => s.Sid !== SID);
  statements.push({
    Sid: SID,
    Effect: "Allow",
    Principal: { Service: "pca-connector-scep.amazonaws.com" },
    Action: ["acm-pca:IssueCertificate", "acm-pca:GetCertificate", "acm-pca:DescribeCertificateAuthority", "acm-pca:GetCertificateAuthorityCertificate"],
    Resource: ca,
    Condition: { StringEquals: { "aws:SourceAccount": account } },
  });
  await c.send(new PutPolicyCommand({ ResourceArn: ca, Policy: JSON.stringify({ ...doc, Statement: statements }) }));
}

export async function createConnector(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const intune = text(form, "type") === "INTUNE";
    const ca = required(form, "ca", "Certificate authority");
    if (text(form, "allow") === "on") await allowConnector(ca, ca.split(":")[4]);
    const out = await (await scep()).send(
      new CreateConnectorCommand({
        CertificateAuthorityArn: ca,
        MobileDeviceManagement: intune ? { Intune: { AzureApplicationId: required(form, "azureApp", "Azure application ID"), Domain: required(form, "azureDomain", "Domain") } } : undefined,
        ClientToken: `console-${Date.now()}`,
      }),
    );
    redirect(`${PAGE}?arn=${encodeURIComponent(out.ConnectorArn!)}`);
  }, {
    fields: {
      CertificateAuthorityArn: "ca",
      BadRequestException: "ca",
      ResourceNotFoundException: "ca",
      AccessDeniedException: "ca",
      "MobileDeviceManagement.Intune.AzureApplicationId": "azureApp",
      "MobileDeviceManagement.Intune.Domain": "azureDomain",
    },
  });
}

export async function deleteConnector(arn: string) {
  return act(async () => {
    await (await scep()).send(new DeleteConnectorCommand({ ConnectorArn: arn }));
    redirect("/pca/connectors");
  });
}

/** A new challenge password, shown on the page right away. */
export async function createChallenge(connector: string) {
  return act(async () => {
    const out = await (await scep()).send(new CreateChallengeCommand({ ConnectorArn: connector, ClientToken: `console-${Date.now()}` }));
    redirect(`${PAGE}?arn=${encodeURIComponent(connector)}&reveal=${encodeURIComponent(out.Challenge!.Arn!)}`);
  });
}

export async function deleteChallenge(challenge: string) {
  return act(async () => {
    await (await scep()).send(new DeleteChallengeCommand({ ChallengeArn: challenge }));
    return "Challenge deleted";
  }, PAGE);
}

export async function saveTags(arn: string, before: string[], _: ActionResult | null, form: FormData) {
  return act(async () => {
    const c = await scep();
    const tags = Object.fromEntries(
      text(form, "tags")
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean)
        .map((l, i) => {
          const [k, ...rest] = l.split("=");
          if (!rest.length || !k.trim()) throw new FieldError("tags", `Line ${i + 1}: key=value`, "format");
          return [k.trim(), rest.join("=").trim()];
        }),
    );
    const gone = before.filter((k) => !(k in tags));
    if (gone.length) await c.send(new UntagResourceCommand({ ResourceArn: arn, TagKeys: gone }));
    if (Object.keys(tags).length) await c.send(new TagResourceCommand({ ResourceArn: arn, Tags: tags }));
    return "Tags saved";
  }, { revalidate: [PAGE], fields: { Tags: "tags" } });
}

"use server";

import {
  CreateDocumentCommand,
  DeleteDocumentCommand,
  ModifyDocumentPermissionCommand,
  UpdateDocumentCommand,
  UpdateDocumentDefaultVersionCommand,
  type DocumentFormat,
  type DocumentType,
} from "@aws-sdk/client-ssm";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { listItems } from "@mws-dashboard/ui/validation";
import { redirect } from "next/navigation";

import { ssm } from "../../../lib/clients";

const docHref = (name: string) => `/ssm/document?name=${encodeURIComponent(name)}`;

const CONTENT_FIELDS = {
  Content: "content",
  InvalidDocumentContent: "content",
  InvalidDocumentSchemaVersion: "content",
  DocumentFormat: "format",
  Name: "name",
  DocumentAlreadyExists: "name",
  VersionName: "versionName",
  DuplicateDocumentVersionName: "versionName",
  DuplicateDocumentContent: "content",
  TargetType: "targetType",
  InvalidTarget: "targetType",
  DocumentType: "type",
  Tags: "tags",
};

function tagLines(form: FormData) {
  return text(form, "tags")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l, i) => {
      const [Key, ...rest] = l.split("=");
      if (!rest.length || !Key.trim()) throw new FieldError("tags", `Line ${i + 1}: key=value`, "format");
      return { Key: Key.trim(), Value: rest.join("=").trim() };
    });
}

export async function createDocument(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    const Tags = tagLines(form);
    await (await ssm()).send(
      new CreateDocumentCommand({
        Name: name,
        Content: required(form, "content", "Content"),
        DocumentType: (text(form, "type") || "Command") as DocumentType,
        DocumentFormat: (text(form, "format") || "YAML") as DocumentFormat,
        TargetType: text(form, "targetType") || undefined,
        VersionName: text(form, "versionName") || undefined,
        DisplayName: text(form, "displayName") || undefined,
        Tags: Tags.length ? Tags : undefined,
      }),
    );
    redirect(docHref(name));
  }, { fields: CONTENT_FIELDS });
}

export async function updateDocument(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await ssm()).send(
      new UpdateDocumentCommand({
        Name: name,
        Content: required(form, "content", "Content"),
        DocumentFormat: (text(form, "format") || "YAML") as DocumentFormat,
        DocumentVersion: "$LATEST",
        VersionName: text(form, "versionName") || undefined,
        TargetType: text(form, "targetType") || undefined,
      }),
    );
    const v = out.DocumentDescription?.DocumentVersion;
    if (text(form, "makeDefault") === "on" && v) await (await ssm()).send(new UpdateDocumentDefaultVersionCommand({ Name: name, DocumentVersion: v }));
    return `Version ${v} created`;
  }, { revalidate: ["/ssm/document", "/ssm/documents"], fields: CONTENT_FIELDS });
}

export async function setDefaultVersion(name: string, version: string) {
  return act(async () => {
    await (await ssm()).send(new UpdateDocumentDefaultVersionCommand({ Name: name, DocumentVersion: version }));
    return `Version ${version} is the default`;
  }, "/ssm/document");
}

export async function deleteDocument(name: string, version?: string) {
  return act(async () => {
    await (await ssm()).send(new DeleteDocumentCommand({ Name: name, DocumentVersion: version }));
    if (!version) redirect("/ssm/documents");
    return `Version ${version} deleted`;
  }, "/ssm/document");
}

export async function share(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const accounts = listItems(required(form, "accounts", "Accounts"));
    await (await ssm()).send(
      new ModifyDocumentPermissionCommand({ Name: name, PermissionType: "Share", AccountIdsToAdd: accounts, SharedDocumentVersion: text(form, "version") || undefined }),
    );
    return `Shared with ${accounts.join(", ")}`;
  }, { revalidate: ["/ssm/document"], fields: { AccountIdsToAdd: "accounts", InvalidPermissionType: "accounts", DocumentPermissionLimit: "accounts", SharedDocumentVersion: "version" } });
}

export async function unshare(name: string, account: string) {
  return act(async () => {
    await (await ssm()).send(new ModifyDocumentPermissionCommand({ Name: name, PermissionType: "Share", AccountIdsToRemove: [account] }));
    return `No longer shared with ${account}`;
  }, "/ssm/document");
}

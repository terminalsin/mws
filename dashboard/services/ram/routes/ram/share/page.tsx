import {
  GetResourceShareAssociationsCommand,
  GetResourceSharesCommand,
  ListPermissionsCommand,
  ListResourceSharePermissionsCommand,
  ListResourcesCommand,
  type ResourceShareAssociation,
} from "@aws-sdk/client-ram";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Section, Segments, Sheet, Specs, Status, SERVICES } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { TagResource, UpdateResourceShare } from "@mws-dashboard/ui/model/ram";
import { Globe, KeyRound, Pencil, Plus, Tag, Trash2, X } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, permissionHref, principalHref, ram, resourceHref, shareTargets } from "../../../lib/clients";
import { shareRules } from "../../../lib/rules";
import { addShareTag, associate, associatePermission, deleteShare, disassociate, disassociatePermission, removeShareTag, updateShare } from "../actions";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

export const metadata: Metadata = { title: "Resource share" };

type Props = { searchParams: Promise<{ arn?: string; tab?: string }> };

const iconFor = (type: string | undefined) => {
  const svc = type?.split(":")[0] ?? "";
  return SERVICES.find((s) => s.id === svc.replace("-", "") || s.endpoints.includes(svc))?.icon ?? ICONS.ram;
};

const principalIcon = (id: string | undefined) =>
  /^\d{12}$/.test(id ?? "") ? ICONS.account : id?.includes(":ou/") ? ICONS.ou : id?.includes(":organizations::") ? ICONS.organizations : ICONS.account;

const TONE: Record<string, "good" | "warn" | "bad" | "neutral"> = { ASSOCIATED: "good", ASSOCIATING: "warn", DISASSOCIATING: "warn", FAILED: "bad", DISASSOCIATED: "neutral" };
const TAG = TagResource.tags.item?.fields ?? {};

const assocStatus = (a: ResourceShareAssociation) => (
  <Status tone={TONE[a.status ?? ""] ?? "neutral"}>
    {a.status?.toLowerCase()}
  </Status>
);

export default async function Share({ searchParams }: Props) {
  const { arn = "", tab = "resources" } = await searchParams;
  const data = await load(async () => {
    const client = await ram();
    const owned = (await client.send(new GetResourceSharesCommand({ resourceOwner: "SELF", resourceShareArns: [arn] }))).resourceShares?.[0];
    const owner = owned ? "SELF" : "OTHER-ACCOUNTS";
    const share = owned ?? (await client.send(new GetResourceSharesCommand({ resourceOwner: "OTHER-ACCOUNTS", resourceShareArns: [arn] }))).resourceShares![0];
    const associations = (associationType: "PRINCIPAL" | "RESOURCE") =>
      all(
        (nextToken) => client.send(new GetResourceShareAssociationsCommand({ associationType, resourceShareArns: [arn], nextToken })),
        (r) => r.resourceShareAssociations,
        (r) => r.nextToken,
      ).then((l) => l.filter((a) => a.status !== "DISASSOCIATED"));
    const [resourceAssocs, principals, resources, permissions] = await Promise.all([
      owned ? associations("RESOURCE") : [],
      owned ? associations("PRINCIPAL") : [],
      all(
        (nextToken) => client.send(new ListResourcesCommand({ resourceOwner: owner, resourceShareArns: [arn], nextToken })),
        (r) => r.resources,
        (r) => r.nextToken,
      ),
      all(
        (nextToken) => client.send(new ListResourceSharePermissionsCommand({ resourceShareArn: arn, nextToken })),
        (r) => r.permissions,
        (r) => r.nextToken,
      ).catch(() => []),
    ]);
    return { share, resourceAssocs, principals, resources, permissions, owned: !!owned };
  });
  const back = { href: "/ram", label: "Shared by me" };
  if (!data.ok) {
    return (
      <Page title="Resource share" icon={ICONS.ram} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { share, resourceAssocs, principals, resources, permissions, owned } = data.value;
  if (!owned) back.href = "/ram?tab=others";
  if (!owned) back.label = "Shared with me";
  // Resources RAM has accepted are in ListResources (with their type);
  // associations show the ones still pending or that failed.
  const listed = new Map(resources.map((r) => [r.arn!, r]));
  const resourceRows = owned
    ? resourceAssocs.map((a) => ({ arn: a.associatedEntity!, type: listed.get(a.associatedEntity!)?.type, assoc: a as ResourceShareAssociation | undefined }))
    : resources.map((r) => ({ arn: r.arn!, type: r.type, assoc: undefined }));
  const settling = [...resourceAssocs, ...principals].some((a) => a.status === "ASSOCIATING" || a.status === "DISASSOCIATING");
  const [targets, allPerms] = owned
    ? await Promise.all([
        shareTargets(),
        (async () =>
          all(
            async (nextToken) => (await ram()).send(new ListPermissionsCommand({ nextToken })),
            (r) => r.permissions,
            (r) => r.nextToken,
          ))().catch(() => []),
      ])
    : [null, []];
  const RULES = shareRules(targets);
  const attached = new Set(permissions.map((p) => p.arn));
  const types = new Set(resourceRows.map((r) => r.type).filter(Boolean));
  const addable = allPerms.filter((p) => !attached.has(p.arn) && (!types.size || types.has(p.resourceType)));
  const href = (t: string) => `/ram/share?arn=${encodeURIComponent(arn)}${t === "resources" ? "" : `&tab=${t}`}`;
  const tabs = [
    { id: "resources", label: "Shared resources", count: resourceRows.length },
    ...(owned ? [{ id: "principals", label: "Shared principals", count: principals.length }] : []),
    { id: "permissions", label: "Managed permissions", count: permissions.length },
    { id: "tags", label: "Tags", count: share.tags?.length ?? 0 },
  ];
  const addSheet = (focus: "resources" | "principals") => (
    <Sheet title={focus === "resources" ? "Add resources" : "Add principals"} label={focus === "resources" ? "Add resources" : "Add principals"} icon={<Plus size={16} />} testId={`add-${focus}`}>
      <ActionForm action={associate.bind(null, arn)} submit="Add" testId={`add-${focus}`}>
        {focus === "resources" ? (
          <Field label="Resource ARNs" rule={RULES.resources} member="resourceArns">
            <ResourcePicker kind={["private-ca", "subnet"]} use="arn" multiple name="resources" defaultValue={((v) => (v ? `${v}, ` : undefined))(targets?.resources.find((r) => !resourceRows.some((x) => x.arn === r)))} />
          </Field>
        ) : (
          <Field label="Principals" rule={RULES.principals} member="principals">
            <textarea name="principals" rows={3} placeholder="111122223333 or an OU / organization ARN" autoFocus />
          </Field>
        )}
      </ActionForm>
    </Sheet>
  );
  return (
    <Page
      title={share.name}
      icon={ICONS.ram}
      back={back}
      subtitle={arn}
      actions={
        owned ? (
          <>
            <Sheet title="Edit resource share" label="Edit resource share" icon={<Pencil size={16} />} testId="edit-share">
              <ActionForm action={updateShare.bind(null, arn)} submit="Save" testId="edit-share">
                <Field label="Name" rule={UpdateResourceShare.name}>
                  <input name="name" required defaultValue={share.name} />
                </Field>
                <label className="check">
                  <input type="checkbox" name="external" defaultChecked={share.allowExternalPrincipals} /> Allow sharing outside the organization
                </label>
              </ActionForm>
            </Sheet>
            <ActionForm action={deleteShare.bind(null, arn)} submit="Delete resource share" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${share.name}?`} testId="delete-share" />
          </>
        ) : undefined
      }
    >
      {settling && <LiveRefresh />}
      <Specs
        items={[
          { label: "Status", icon: <AwsIcon icon={ICONS.ram} size={16} />, value: <Status tone={share.status === "ACTIVE" ? "good" : share.status === "FAILED" ? "bad" : "warn"}>{share.status?.toLowerCase()}</Status> },
          { label: "External principals", icon: <Globe size={15} />, value: share.allowExternalPrincipals ? "Allowed" : "Not allowed" },
          !owned && { label: "Owner", icon: <AwsIcon icon={ICONS.account} size={16} />, value: share.owningAccountId },
          share.featureSet && share.featureSet !== "STANDARD" && { label: "Feature set", icon: <AwsIcon icon={ICONS.ram} size={16} />, value: share.featureSet.toLowerCase() },
          { label: "Created", icon: <AwsIcon icon={ICONS.ram} size={16} />, value: ago(share.creationTime) },
        ]}
      />
      {share.statusMessage && <div className="banner">{share.statusMessage}</div>}
      <Segments label="Share" items={tabs.map((t) => ({ label: t.label, href: href(t.id), active: t.id === tab, count: t.count }))} />
      {tab === "resources" && (
        <Section title="Shared resources" count={resourceRows.length} plain actions={owned ? addSheet("resources") : undefined}>
          <List
            label="Shared resources"
            empty={<Empty icon={ICONS.ram} />}
            rows={resourceRows.map((r) => ({
              key: r.arn,
              icon: <AwsIcon icon={iconFor(r.type ?? r.arn.split(":")[2])} size={22} />,
              title: r.arn.split(/[:/]/).pop(),
              subtitle: r.assoc?.status === "FAILED" ? r.assoc.statusMessage : (r.type ?? r.arn),
              href: resourceHref(r.arn),
              meta: r.assoc ? assocStatus(r.assoc) : <Status tone={listed.get(r.arn)?.status === "AVAILABLE" ? "good" : "warn"}>{listed.get(r.arn)?.status?.toLowerCase()}</Status>,
              actions: owned ? <ActionForm action={disassociate.bind(null, arn, "resource", r.arn)} submit={`Remove ${r.arn.split(/[:/]/).pop()}`} icon={<X size={15} />} tone="danger" confirm="Stop sharing this resource?" /> : undefined,
            }))}
          />
        </Section>
      )}
      {tab === "principals" && owned && (
        <Section title="Shared principals" count={principals.length} plain actions={addSheet("principals")}>
          <List
            label="Principals"
            empty={<Empty icon={ICONS.account} />}
            rows={principals.map((p) => ({
              key: p.associatedEntity!,
              icon: <AwsIcon icon={principalIcon(p.associatedEntity)} size={22} />,
              title: p.associatedEntity,
              subtitle: p.statusMessage,
              href: principalHref(p.associatedEntity),
              meta: (
                <>
                  {p.external && <Globe size={13} aria-label="External" />}
                  {assocStatus(p)}
                  <span>{ago(p.lastUpdatedTime ?? p.creationTime)}</span>
                </>
              ),
              actions: <ActionForm action={disassociate.bind(null, arn, "principal", p.associatedEntity!)} submit={`Remove ${p.associatedEntity}`} icon={<X size={15} />} tone="danger" confirm={`Stop sharing with ${p.associatedEntity}?`} />,
            }))}
          />
        </Section>
      )}
      {tab === "permissions" && (
        <Section
          title="Managed permissions"
          count={permissions.length}
          plain
          actions={
            owned && addable.length > 0 ? (
              <Sheet title="Associate permission" label="Associate permission" icon={<KeyRound size={16} />} testId="associate-permission">
                <ActionForm action={associatePermission.bind(null, arn)} submit="Associate" testId="associate-permission">
                  <Field label="Permission" member="permissionArn">
                    <select name="permission" required>
                      {addable.map((p) => (
                        <option key={p.arn} value={p.arn}>
                          {p.name} · {p.resourceType}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <label className="check">
                    <input type="checkbox" name="replace" /> Replace the permission for this resource type
                  </label>
                </ActionForm>
              </Sheet>
            ) : undefined
          }
        >
          <List
            label="Permissions"
            empty={<Empty icon={ICONS.ram} />}
            rows={permissions.map((p) => ({
              key: p.arn!,
              icon: <AwsIcon icon={ICONS.ram} size={22} />,
              title: p.name,
              subtitle: p.resourceType,
              href: permissionHref(p.arn, p.version),
              meta: (
                <>
                  <Pill>{p.permissionType === "CUSTOMER_MANAGED" ? "Customer managed" : "AWS managed"}</Pill>
                  <span>v{p.version}</span>
                  {p.defaultVersion === false && <Status tone="warn">not default</Status>}
                </>
              ),
              actions:
                owned && permissions.length > 1 ? (
                  <ActionForm action={disassociatePermission.bind(null, arn, p.arn!)} submit={`Remove ${p.name}`} icon={<X size={15} />} tone="danger" confirm={`Remove ${p.name} from this share?`} />
                ) : undefined,
            }))}
          />
        </Section>
      )}
      {tab === "tags" && (
        <Section
          title="Tags"
          count={share.tags?.length ?? 0}
          plain
          actions={
            owned ? (
              <Sheet title="Add tag" label="Add tag" testId="add-share-tag">
                <ActionForm action={addShareTag.bind(null, arn)} submit="Add tag" testId="add-share-tag">
                  <div className="form-row">
                    <Field label="Key" rule={TAG.key}>
                      <input name="key" required />
                    </Field>
                    <Field label="Value" rule={TAG.value}>
                      <input name="value" />
                    </Field>
                  </div>
                </ActionForm>
              </Sheet>
            ) : undefined
          }
        >
          <List
            label="Tags"
            empty={<Empty icon={ICONS.ram} />}
            rows={(share.tags ?? []).map((t) => ({
              key: t.key!,
              icon: <Tag size={16} />,
              title: t.key,
              subtitle: t.value,
              actions: owned ? <ActionForm action={removeShareTag.bind(null, arn, t.key!)} submit={`Remove tag ${t.key}`} icon={<X size={15} />} tone="danger" /> : undefined,
            }))}
          />
        </Section>
      )}
    </Page>
  );
}

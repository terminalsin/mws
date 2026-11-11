import { DescribeAddonVersionsCommand, DescribeClusterCommand, DescribeClusterVersionsCommand, ListAccessPoliciesCommand, type Update } from "@aws-sdk/client-eks";
import { all, load, region, shortName, when } from "@mws-dashboard/aws";
import { ActionForm, AutoPick, AwsIcon, CodeBlock, CopyValue, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Specs, Status, Tags, type Rule, freeName } from "@mws-dashboard/ui";
import { CreateAccessEntry, CreateAddon, CreateFargateProfile, CreateNodegroup } from "@mws-dashboard/ui/model/eks";
import { ArrowUpCircle, Clock, Globe, KeyRound, Lock, Plus, Puzzle, ScrollText, Shield, Trash2, TriangleAlert, UserPlus } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, STATUS_TONE, eks } from "../../../lib/clients";
import { accessEntries, addons as listAddons, fargateProfiles, nextMinor, nodegroups, updates as listUpdates } from "../../../lib/data";
import { instanceTypes, rolesTrusting } from "../../../lib/eks";
import { AddonFields, NodegroupFields } from "../../../lib/forms.tsx";
import { addonIcon } from "../../../lib/presets";
import {
  associatePolicy,
  createAccessEntry,
  createAddon,
  createFargateProfile,
  createNodegroup,
  deleteAccessEntry,
  deleteAddon,
  deleteCluster,
  deleteFargateProfile,
  disassociatePolicy,
  updateAddon,
  updateClusterConfig,
  upgradeCluster,
} from "../actions";
import { UpdateRows } from "../updates.tsx";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

export const metadata: Metadata = { title: "Cluster" };

// The model leaves node group names open; these are the rules in EKS's docs.
const NODEGROUP_NAME: Rule = {
  ...CreateNodegroup.nodegroupName,
  maxLength: 63,
  pattern: "^[0-9A-Za-z][A-Za-z0-9_-]*$",
  hint: "Letters, digits, - and _, starting with a letter or digit",
  generate: "name",
};
const PROFILE_NAME: Rule = {
  ...CreateFargateProfile.fargateProfileName,
  maxLength: 63,
  pattern: "^[0-9A-Za-z][A-Za-z0-9_-]*$",
  hint: "Letters, digits, - and _",
  generate: "name",
};
const PRINCIPAL: Rule = {
  ...CreateAccessEntry.principalArn,
  required: true,
  pattern: "^arn:aws[a-z-]*:(iam|sts)::\\d{12}:(role|user|assumed-role)/.+$",
  hint: "An IAM role or user ARN",
};

type Props = { searchParams: Promise<{ name?: string; tab?: string }> };

export default async function Cluster({ searchParams }: Props) {
  const { name = "", tab = "overview" } = await searchParams;
  const back = { href: "/eks", label: "Clusters" };
  const here = `/eks/cluster?name=${encodeURIComponent(name)}`;
  const data = await load(async () => {
    const client = await eks();
    const c = (await client.send(new DescribeClusterCommand({ name }))).cluster!;
    const [groups, profiles, addons, updates] = await Promise.all([
      nodegroups(name),
      c.connectorConfig ? Promise.resolve([]) : fargateProfiles(name),
      listAddons(name),
      tab === "updates" || tab === "overview" ? listUpdates(name) : Promise.resolve([] as Update[]),
    ]);
    return { c, groups, profiles, addons, updates };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.eks} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { c, groups, profiles, addons, updates } = data.value;
  const vpc = c.resourcesVpcConfig;
  const subnets = vpc?.subnetIds ?? [];
  const registered = !!c.connectorConfig;
  const target = nextMinor(c.version);
  const busy = c.status !== "ACTIVE";
  const [nodeRoles, fargateRoles, types, versions, offered, policies, entries] = await Promise.all([
    tab === "compute" ? rolesTrusting("ec2.amazonaws.com").catch(() => []) : Promise.resolve([]),
    tab === "compute" ? rolesTrusting("eks-fargate-pods.amazonaws.com").catch(() => []) : Promise.resolve([]),
    tab === "compute" ? instanceTypes().catch(() => [] as string[]) : Promise.resolve([] as string[]),
    load(async () => (await (await eks()).send(new DescribeClusterVersionsCommand({}))).clusterVersions ?? []),
    tab === "addons"
      ? load(async () => {
          const client = await eks();
          return all(
            (nextToken) =>
              client.send(
                new DescribeAddonVersionsCommand({
                  kubernetesVersion: c.version,
                  nextToken,
                }),
              ),
            (r) => r.addons,
            (r) => r.nextToken,
          );
        })
      : null,
    tab === "access"
      ? load(async () => {
          const client = await eks();
          return all(
            (nextToken) => client.send(new ListAccessPoliciesCommand({ nextToken })),
            (r) => r.accessPolicies,
            (r) => r.nextToken,
          );
        })
      : null,
    tab === "access" ? load(() => accessEntries(name)) : null,
  ]);
  const upgradable = target && versions.ok && versions.value.some((v) => v.clusterVersion === target);
  const behind = groups.filter((g) => g.version && g.version !== c.version);
  const inProgress = updates.filter((u) => u.status === "InProgress");
  const blocking = [groups.length && `${groups.length} node groups`, profiles.length && `${profiles.length} Fargate profiles`].filter(Boolean);

  return (
    <Page
      title={name}
      icon={ICONS.eks}
      back={back}
      subtitle={c.arn}
      actions={
        <>
          {upgradable && (
            <Sheet title="Upgrade version" label="Upgrade version" icon={<ArrowUpCircle size={16} />} testId="upgrade-cluster">
              <ActionForm action={upgradeCluster.bind(null, name)} submit="Upgrade" testId="upgrade-cluster">
                <Field label="Kubernetes version">
                  <select name="version" defaultValue={target}>
                    <option value={target}>
                      {c.version} → {target}
                    </option>
                  </select>
                </Field>
                {behind.length > 0 && (
                  <p className="muted">
                    <TriangleAlert size={13} /> Node groups on older versions: {behind.map((g) => `${g.nodegroupName} (${g.version})`).join(", ")}
                  </p>
                )}
                <label className="check">
                  <input type="checkbox" name="force" /> Upgrade even if node groups are too far behind
                </label>
              </ActionForm>
            </Sheet>
          )}
          <ActionForm
            action={deleteCluster.bind(null, name)}
            submit="Delete cluster"
            icon={<Trash2 size={16} />}
            tone="danger"
            confirm={blocking.length ? `${name} still has ${blocking.join(" and ")}; EKS refuses to delete it until they are deleted (Compute tab). Try anyway?` : `Delete ${name}?`}
            testId="delete-eks-cluster"
          />
        </>
      }
    >
      <Specs
        items={[
          {
            label: "Kubernetes version",
            icon: <AwsIcon icon="brand/kubernetes" size={16} />,
            value: c.version,
          },
          {
            label: "Status",
            icon: <AwsIcon icon={ICONS.eks} size={16} />,
            value: <Status tone={STATUS_TONE(c.status)}>{c.status?.toLowerCase() ?? ""}</Status>,
          },
          vpc && {
            label: "Endpoint access",
            icon: vpc.endpointPublicAccess ? <Globe size={15} /> : <Lock size={15} />,
            value: [vpc.endpointPublicAccess && "Public", vpc.endpointPrivateAccess && "Private"].filter(Boolean).join(" and ") || "None",
          },
          vpc?.vpcId && {
            label: "VPC",
            icon: <AwsIcon icon={ICONS.vpc} size={16} />,
            value: <Link href={`/vpc/${vpc.vpcId}`}>{vpc.vpcId}</Link>,
          },
          c.platformVersion && {
            label: "Platform version",
            icon: <Clock size={15} />,
            value: c.platformVersion,
          },
          c.health?.issues?.length && {
            label: "Health",
            icon: <TriangleAlert size={15} />,
            value: <Pill tone="bad">{c.health.issues.length} issues</Pill>,
          },
          inProgress.length > 0 && {
            label: "Updating",
            icon: <ArrowUpCircle size={15} />,
            value: <Status tone="warn">{inProgress.length === 1 ? "update in progress" : `${inProgress.length} updates in progress`}</Status>,
          },
        ]}
      />
      <Segments
        label="Cluster"
        items={[
          { label: "Overview", href: here, active: tab === "overview" },
          {
            label: "Compute",
            href: `${here}&tab=compute`,
            active: tab === "compute",
            count: groups.length + profiles.length || undefined,
          },
          {
            label: "Networking",
            href: `${here}&tab=networking`,
            active: tab === "networking",
          },
          {
            label: "Add-ons",
            href: `${here}&tab=addons`,
            active: tab === "addons",
            count: addons.length || undefined,
          },
          {
            label: "Access",
            href: `${here}&tab=access`,
            active: tab === "access",
          },
          {
            label: "Update history",
            href: `${here}&tab=updates`,
            active: tab === "updates",
          },
          { label: "Tags", href: `${here}&tab=tags`, active: tab === "tags" },
        ]}
      />
      {tab === "overview" && (
        <>
          {c.health?.issues?.length ? (
            <div className="banner error" role="alert">
              {c.health.issues.map((i) => `${i.code}: ${i.message}`).join("; ")}
            </div>
          ) : null}
          {inProgress.length > 0 && (
            <Section title="Updates in progress" plain>
              <UpdateRows updates={inProgress} />
            </Section>
          )}
          <Section
            title="Details"
            actions={
              !busy && (
                <Sheet title="Manage logging" label="Manage control plane logging" icon={<ScrollText size={15} />} testId="cluster-logging">
                  <ActionForm action={updateClusterConfig.bind(null, name, "logging")} submit="Save" testId="cluster-logging">
                    {(["api", "audit", "authenticator", "controllerManager", "scheduler"] as const).map((t) => (
                      <label key={t} className="check">
                        <input type="checkbox" name={t} defaultChecked={c.logging?.clusterLogging?.some((l) => l.enabled && l.types?.includes(t))} /> {t}
                      </label>
                    ))}
                  </ActionForm>
                </Sheet>
              )
            }
          >
            <Facts
              items={[
                c.endpoint && [
                  "API server endpoint",
                  <CopyValue key="e" value={c.endpoint} label="Copy endpoint" />,
                ],
                c.identity?.oidc?.issuer && [
                  "OpenID Connect provider URL",
                  <CopyValue key="o" value={c.identity.oidc.issuer} label="Copy issuer URL" />,
                ],
                c.roleArn && [
                  "Cluster IAM role",
                  <Link key="r" href={`/iam/roles/${c.roleArn.split("/").pop()}`}>
                    {c.roleArn.split("/").pop()}
                  </Link>,
                ],
                c.accessConfig?.authenticationMode && ["Authentication mode", c.accessConfig.authenticationMode],
                c.certificateAuthority?.data && [
                  "Certificate authority",
                  <code key="c" className="clip">
                    {c.certificateAuthority.data.slice(0, 48)}…
                  </code>,
                ],
                c.encryptionConfig?.length && ["Secrets encryption", c.encryptionConfig.map((e) => shortName(e.provider?.keyArn)).join(", ")],
                c.logging?.clusterLogging && [
                  "Control plane logging",
                  c.logging.clusterLogging
                    .filter((l) => l.enabled)
                    .flatMap((l) => l.types ?? [])
                    .join(", ") || "Off",
                ],
                c.upgradePolicy?.supportType && ["Support", c.upgradePolicy.supportType.toLowerCase()],
                c.deletionProtection && [
                  "Deletion protection",
                  <Pill key="d" tone="info">
                    On
                  </Pill>,
                ],
                ["Created", when(c.createdAt)],
              ]}
            />
          </Section>
          <Section title="Connect">
            <CodeBlock value={`aws eks update-kubeconfig --region ${await region()} --name ${name}\nkubectl get nodes`} label="kubeconfig" />
          </Section>
        </>
      )}
      {tab === "compute" && (
        <>
          <Section
            title="Node groups"
            count={groups.length}
            plain
            actions={
              !registered && (
                <Sheet title="Add node group" label="Add node group" icon={<Plus size={16} />} testId="create-nodegroup">
                  <ActionForm action={createNodegroup.bind(null, name, subnets)} submit="Create" testId="create-nodegroup">
                    <NodegroupFields rule={NODEGROUP_NAME} taken={groups.map((g) => g.nodegroupName!)} types={types}>
                      <AutoPick
                        name="role"
                        label="Node IAM role"
                        creates="AmazonEKSNodeRole"
                        options={nodeRoles.map((r) => ({
                          value: r.Arn!,
                          label: r.RoleName!,
                        }))}
                        testId="node-role"
                      />
                    </NodegroupFields>
                  </ActionForm>
                </Sheet>
              )
            }
          >
            <List
              label="Node groups"
              empty={<Empty icon={ICONS.eks} />}
              rows={groups.map((g) => {
                const issues = g.health?.issues ?? [];
                return {
                  key: g.nodegroupArn!,
                  icon: <AwsIcon icon="resource/AmazonEC2Instances" size={22} />,
                  title: g.nodegroupName,
                  href: `/eks/nodegroup?cluster=${encodeURIComponent(name)}&name=${encodeURIComponent(g.nodegroupName!)}`,
                  subtitle: issues.length ? <span className="row-subtitle">{issues.map((i) => i.code).join(", ")}</span> : `${g.instanceTypes?.join(", ")} · ${g.amiType}`,
                  meta: (
                    <>
                      {g.capacityType === "SPOT" && <Pill tone="info">Spot</Pill>}
                      {g.version && g.version !== c.version && <Pill tone="warn">v{g.version}</Pill>}
                      <span title="Min / desired / max">
                        {g.scalingConfig?.minSize} / {g.scalingConfig?.desiredSize} / {g.scalingConfig?.maxSize}
                      </span>
                      <Status tone={issues.length ? "bad" : STATUS_TONE(g.status)}>{g.status?.toLowerCase().replace(/_/g, " ") ?? ""}</Status>
                    </>
                  ),
                };
              })}
            />
          </Section>
          {!registered && (
            <Section
              title="Fargate profiles"
              count={profiles.length}
              plain
              actions={
                <Sheet title="Add Fargate profile" label="Add Fargate profile" icon={<Plus size={16} />} testId="create-fargate-profile">
                  <ActionForm action={createFargateProfile.bind(null, name, subnets)} submit="Create" testId="create-fargate-profile">
                    <Field label="Name" rule={PROFILE_NAME} taken={profiles.map((p) => p.fargateProfileName!)} unique>
                      <input name="name" autoFocus defaultValue={freeName("default", profiles.map((p) => p.fargateProfileName!))} />
                    </Field>
                    <AutoPick
                      name="role"
                      label="Pod execution role"
                      creates="AmazonEKSFargatePodExecutionRole"
                      options={fargateRoles.map((r) => ({
                        value: r.Arn!,
                        label: r.RoleName!,
                      }))}
                      testId="fargate-role"
                    />
                    <div className="form-row">
                      <Field
                        label="Namespace"
                        rule={{
                          required: true,
                          maxLength: 63,
                          pattern: "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$",
                          hint: "A Kubernetes namespace",
                        }}
                      >
                        <input name="namespace" defaultValue="default" spellCheck={false} />
                      </Field>
                      <Field label="Labels" format="pairs">
                        <textarea name="labels" rows={2} spellCheck={false} placeholder="app=web" />
                      </Field>
                    </div>
                  </ActionForm>
                </Sheet>
              }
            >
              <List
                label="Fargate profiles"
                empty={<Empty>No Fargate profiles</Empty>}
                rows={profiles.map((p) => ({
                  key: p.fargateProfileArn!,
                  icon: <AwsIcon icon="service/AWSFargate" size={22} />,
                  title: p.fargateProfileName,
                  subtitle: (p.selectors ?? [])
                    .map(
                      (s) =>
                        `${s.namespace}${
                          s.labels && Object.keys(s.labels).length
                            ? ` · ${Object.entries(s.labels)
                                .map(([k, v]) => `${k}=${v}`)
                                .join(", ")}`
                            : ""
                        }`,
                    )
                    .join("; "),
                  meta: <Status tone={STATUS_TONE(p.status)}>{p.status?.toLowerCase().replace(/_/g, " ") ?? ""}</Status>,
                  actions:
                    p.status === "ACTIVE" || p.status === "CREATE_FAILED" ? (
                      <ActionForm
                        action={deleteFargateProfile.bind(null, name, p.fargateProfileName!)}
                        submit={`Delete ${p.fargateProfileName}`}
                        icon={<Trash2 size={15} />}
                        tone="danger"
                        confirm={`Delete ${p.fargateProfileName}?`}
                      />
                    ) : undefined,
                }))}
              />
            </Section>
          )}
        </>
      )}
      {tab === "networking" && vpc && (
        <Section
          actions={
            !busy && (
              <Sheet title="Manage endpoint access" label="Manage endpoint access" icon={<Globe size={15} />} testId="endpoint-access">
                <ActionForm action={updateClusterConfig.bind(null, name, "endpoint")} submit="Save" testId="endpoint-access">
                  <div className="form-row">
                    <label className="check">
                      <input type="checkbox" name="public" defaultChecked={!!vpc.endpointPublicAccess} /> Public
                    </label>
                    <label className="check">
                      <input type="checkbox" name="private" defaultChecked={!!vpc.endpointPrivateAccess} /> Private
                    </label>
                  </div>
                  <Field label="Public access sources" rule={{ type: "list", item: { type: "string", format: "cidr" } }} hint="CIDR blocks; empty: 0.0.0.0/0">
                    <input name="cidrs" spellCheck={false} defaultValue={(vpc.publicAccessCidrs ?? []).join(", ")} />
                  </Field>
                </ActionForm>
              </Sheet>
            )
          }
        >
          <Facts
            items={[
              vpc.vpcId && [
                "VPC",
                <Link key="v" href={`/vpc/${vpc.vpcId}`}>
                  {vpc.vpcId}
                </Link>,
              ],
              subnets.length > 0 && ["Subnets", subnets.join(", ")],
              vpc.clusterSecurityGroupId && [
                "Cluster security group",
                <Link key="c" href={`/ec2/group?id=${encodeURIComponent(vpc.clusterSecurityGroupId)}`}>
                  <Pill icon={<Shield size={12} />}>{vpc.clusterSecurityGroupId}</Pill>
                </Link>,
              ],
              vpc.securityGroupIds?.length && [
                "Additional security groups",
                <span key="g" className="chips">
                  {vpc.securityGroupIds.map((g) => (
                    <Link key={g} href={`/ec2/group?id=${encodeURIComponent(g)}`}>
                      <Pill icon={<Shield size={12} />}>{g}</Pill>
                    </Link>
                  ))}
                </span>,
              ],
              c.kubernetesNetworkConfig?.serviceIpv4Cidr && ["Service IPv4 range", c.kubernetesNetworkConfig.serviceIpv4Cidr],
              c.kubernetesNetworkConfig?.ipFamily && ["IP family", c.kubernetesNetworkConfig.ipFamily],
              ["API server endpoint access", [vpc.endpointPublicAccess && "Public", vpc.endpointPrivateAccess && "Private"].filter(Boolean).join(" and ") || "None"],
              vpc.endpointPublicAccess &&
                vpc.publicAccessCidrs?.length && [
                  "Public access sources",
                  vpc.publicAccessCidrs.includes("0.0.0.0/0") ? (
                    <Pill key="p" tone="warn" icon={<Globe size={12} />}>
                      0.0.0.0/0
                    </Pill>
                  ) : (
                    vpc.publicAccessCidrs.join(", ")
                  ),
                ],
            ]}
          />
        </Section>
      )}
      {tab === "addons" && (
        <Section
          title="Add-ons"
          count={addons.length}
          plain
          actions={
            offered?.ok && (
              <Sheet title="Get more add-ons" label="Get more add-ons" icon={<Plus size={16} />} testId="create-addon">
                <ActionForm action={createAddon.bind(null, name)} submit="Create" testId="create-addon">
                  <AddonFields
                    offered={offered.value
                      .filter((a) => !addons.some((x) => x.addonName === a.addonName))
                      .map((a) => ({
                        name: a.addonName!,
                        publisher: a.publisher,
                        versions: (a.addonVersions ?? []).map((v) => v.addonVersion!),
                        default: a.addonVersions?.find((v) => v.compatibilities?.some((x) => x.defaultVersion))?.addonVersion,
                      }))}
                  />
                </ActionForm>
              </Sheet>
            )
          }
        >
          {offered && !offered.ok && <ErrorNotice error={offered.error} />}
          <List
            label="Add-ons"
            empty={<Empty>No add-ons</Empty>}
            rows={addons.map((a) => {
              const versionsOf = offered?.ok ? (offered.value.find((x) => x.addonName === a.addonName)?.addonVersions ?? []).map((v) => v.addonVersion!) : [];
              const newer = versionsOf.filter((v) => v !== a.addonVersion);
              const issues = a.health?.issues ?? [];
              return {
                key: a.addonArn ?? a.addonName!,
                icon: addonIcon(a.addonName) ? <AwsIcon icon={addonIcon(a.addonName)!} size={22} /> : <Puzzle size={18} aria-hidden />,
                title: a.addonName,
                subtitle: issues.length ? <span className="row-subtitle">{issues.map((i) => `${i.code}: ${i.message}`).join("; ")}</span> : a.addonVersion,
                meta: (
                  <>
                    {a.publisher && <span>{a.publisher}</span>}
                    {a.serviceAccountRoleArn && (
                      <Pill icon={<KeyRound size={12} />} title={a.serviceAccountRoleArn}>
                        IRSA
                      </Pill>
                    )}
                    <Status tone={issues.length ? "bad" : STATUS_TONE(a.status)}>{a.status?.toLowerCase().replace(/_/g, " ") ?? ""}</Status>
                  </>
                ),
                actions: (
                  <>
                    <AddonUpdate cluster={name} addon={a.addonName!} version={a.addonVersion} versions={newer} config={a.configurationValues} />
                    <ActionForm action={deleteAddon.bind(null, name, a.addonName!)} submit={`Delete ${a.addonName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Remove ${a.addonName}?`} />
                  </>
                ),
              };
            })}
          />
        </Section>
      )}
      {tab === "access" && (
        <>
          <Section>
            <Facts
              items={[
                ["Authentication mode", c.accessConfig?.authenticationMode ?? "CONFIG_MAP"],
                c.accessConfig?.authenticationMode === "CONFIG_MAP" && [
                  "Access entries",
                  <Pill key="a" tone="warn">
                    Need API or API_AND_CONFIG_MAP
                  </Pill>,
                ],
              ]}
            />
          </Section>
          <Section
            title="IAM access entries"
            count={entries?.ok ? entries.value.length : undefined}
            plain
            actions={
              c.accessConfig?.authenticationMode !== "CONFIG_MAP" && (
                <Sheet title="Create access entry" label="Create access entry" icon={<UserPlus size={16} />} testId="create-access-entry">
                  <ActionForm action={createAccessEntry.bind(null, name)} submit="Create" testId="create-access-entry">
                    <Field label="IAM principal ARN" rule={PRINCIPAL} taken={entries?.ok ? entries.value.map((e) => e.principalArn!) : []} unique>
                      <ResourcePicker kind={["iam-role", "iam-user"]} use="arn" name="principal" required />
                    </Field>
                    <div className="form-row">
                      <Field label="Type">
                        <select name="type" defaultValue="STANDARD">
                          <option value="STANDARD">Standard</option>
                          <option value="EC2_LINUX">EC2 Linux</option>
                          <option value="EC2_WINDOWS">EC2 Windows</option>
                          <option value="FARGATE_LINUX">Fargate Linux</option>
                        </select>
                      </Field>
                      <Field label="Kubernetes groups">
                        <input name="groups" spellCheck={false} placeholder="optional, comma separated" />
                      </Field>
                    </div>
                    <PolicyFields
                      policies={
                        policies?.ok
                          ? policies.value.map((p) => ({
                              arn: p.arn!,
                              name: p.name!,
                            }))
                          : []
                      }
                      optional
                    />
                  </ActionForm>
                </Sheet>
              )
            }
          >
            {entries && !entries.ok && <ErrorNotice error={entries.error} />}
            <List
              label="Access entries"
              empty={<Empty>No access entries</Empty>}
              rows={(entries?.ok ? entries.value : []).map((e) => ({
                key: e.principalArn!,
                icon: <KeyRound size={18} aria-hidden />,
                title: e.principalArn!.split("/").pop(),
                subtitle: e.principalArn,
                meta: (
                  <span className="chips">
                    {e.policies.map((p) => (
                      <Pill key={p.policyArn} title={p.accessScope?.type === "namespace" ? `Namespaces: ${p.accessScope.namespaces?.join(", ")}` : "Cluster"}>
                        {p.policyArn?.split("/").pop()}
                        {p.accessScope?.type === "namespace" ? ` (${p.accessScope.namespaces?.length} ns)` : ""}
                      </Pill>
                    ))}
                  </span>
                ),
                actions: (
                  <>
                    <Sheet
                      title={`Associate policy with ${e.principalArn!.split("/").pop()}`}
                      label={`Associate access policy with ${e.principalArn!.split("/").pop()}`}
                      icon={<Plus size={15} />}
                      testId={`associate-${e.principalArn!.split("/").pop()}`}
                    >
                      <ActionForm action={associatePolicy.bind(null, name, e.principalArn!)} submit="Associate" testId={`associate-${e.principalArn!.split("/").pop()}`}>
                        <PolicyFields
                          policies={
                            policies?.ok
                              ? policies.value.map((p) => ({
                                  arn: p.arn!,
                                  name: p.name!,
                                }))
                              : []
                          }
                        />
                      </ActionForm>
                    </Sheet>
                    {e.policies.map((p) => (
                      <ActionForm
                        key={p.policyArn}
                        action={disassociatePolicy.bind(null, name, e.principalArn!, p.policyArn!)}
                        submit={`Remove ${p.policyArn?.split("/").pop()}`}
                        icon={<Lock size={15} />}
                        confirm={`Remove ${p.policyArn?.split("/").pop()} from ${e.principalArn!.split("/").pop()}?`}
                      />
                    ))}
                    <ActionForm
                      action={deleteAccessEntry.bind(null, name, e.principalArn!)}
                      submit={`Delete ${e.principalArn!.split("/").pop()}`}
                      icon={<Trash2 size={15} />}
                      tone="danger"
                      confirm={`Delete the access entry for ${e.principalArn}?`}
                    />
                  </>
                ),
              }))}
            />
          </Section>
        </>
      )}
      {tab === "updates" && <UpdateRows updates={updates} empty />}
      {tab === "tags" && (c.tags && Object.keys(c.tags).length ? <Tags tags={c.tags} /> : <Empty>No tags</Empty>)}
    </Page>
  );
}

function PolicyFields({ policies, optional }: { policies: { arn: string; name: string }[]; optional?: boolean }) {
  return (
    <div className="form-row">
      <Field label="Access policy">
        <select name="policy" defaultValue={optional ? "" : policies.find((p) => p.name === "AmazonEKSViewPolicy")?.arn} required={!optional}>
          {optional && <option value="">None</option>}
          {policies.map((p) => (
            <option key={p.arn} value={p.arn}>
              {p.name}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Namespaces" hint="Empty: the whole cluster">
        <input name="namespaces" spellCheck={false} placeholder="optional" />
      </Field>
    </div>
  );
}

function AddonUpdate({ cluster, addon, version, versions, config }: { cluster: string; addon: string; version?: string; versions: string[]; config?: string }) {
  return (
    <Sheet title={`Update ${addon}`} label={`Update ${addon}`} icon={<ArrowUpCircle size={15} />} testId={`update-addon-${addon}`}>
      <ActionForm action={updateAddon.bind(null, cluster, addon)} submit="Update" testId={`update-addon-${addon}`}>
        <Field label="Version">
          <select name="version" defaultValue={version}>
            {version && <option value={version}>{version} (current)</option>}
            {versions.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Configuration values" format="jsonish">
          <textarea name="config" rows={4} spellCheck={false} defaultValue={config} />
        </Field>
      </ActionForm>
    </Sheet>
  );
}

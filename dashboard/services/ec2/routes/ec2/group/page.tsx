import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Facts, List, Page, Section, Segments, Sheet, Specs, Tags, CopyValue } from "@mws-dashboard/ui";
import { ArrowDownLeft, ArrowUpRight, Network, Plus, Server, ShieldAlert, Trash2, X } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, LINKS, nameTag } from "../../../lib/clients";
import { describeRule, listGroups, listInstances, listPrefixLists, listRules, listVpcs } from "../../../lib/ec2";
import { RuleFields, type Peers } from "../../../lib/rule-fields";
import { TagsSheet } from "../../../lib/widgets";
import { addRule, deleteSecurityGroup, revokeRule } from "../actions";

type Props = { searchParams: Promise<{ id?: string; tab?: string }> };

export const metadata: Metadata = { title: "Security group" };

export default async function GroupPage({ searchParams }: Props) {
  const { id = "", tab = "inbound" } = await searchParams;
  const back = { href: "/ec2?tab=groups", label: "Security groups" };
  const group = await load(async () => {
    const g = (await listGroups([{ Name: "group-id", Values: [id] }]))[0];
    if (!g) throw new Error(`The security group '${id}' does not exist`);
    return g;
  });
  if (!group.ok) {
    return (
      <Page title={id} icon={ICONS.sg} back={back}>
        <ErrorNotice error={group.error} />
      </Page>
    );
  }
  const g = group.value;
  const [rules, groups, prefixLists, vpcs, users] = await Promise.all([
    load(() => listRules([{ Name: "group-id", Values: [id] }])),
    load(() => listGroups()),
    load(listPrefixLists),
    load(listVpcs),
    load(() => listInstances([{ Name: "instance.group-id", Values: [id] }])),
  ]);
  const groupList = groups.ok ? groups.value : [];
  const groupName = (gid?: string) => groupList.find((x) => x.GroupId === gid)?.GroupName ?? gid;
  const vpc = vpcs.ok ? vpcs.value.find((x) => x.VpcId === g.VpcId) : undefined;
  const peers: Peers = {
    groups: groupList.map((x) => ({ id: x.GroupId!, name: x.GroupName!, vpc: x.VpcId })),
    prefixLists: (prefixLists.ok ? prefixLists.value : []).map((p) => ({ id: p.PrefixListId!, name: p.PrefixListName ?? p.PrefixListId! })),
    aliases: Object.fromEntries((vpcs.ok ? vpcs.value : []).flatMap((v) => (v.CidrBlock ? [[nameTag(v) ?? v.VpcId!, v.CidrBlock]] : []))),
  };
  const all = rules.ok ? rules.value : [];
  const direction = tab === "outbound" ? "egress" : "ingress";
  const shown = all.filter((r) => !!r.IsEgress === (direction === "egress")).map((r) => ({ rule: r, ...describeRule(r) }));
  const exposed = all.filter((r) => describeRule(r).exposed).length;
  const here = LINKS.group(id);
  const instances = users.ok ? users.value.filter((i) => i.State?.Name !== "terminated") : [];
  const word = direction === "ingress" ? "inbound" : "outbound";
  return (
    <Page
      title={g.GroupName}
      icon={ICONS.sg}
      back={back}
      subtitle={<CopyValue value={id} />}
      actions={
        g.GroupName !== "default" && (
          <ActionForm
            action={deleteSecurityGroup.bind(null, id, "/ec2?tab=groups")}
            submit="Delete security group"
            icon={<Trash2 size={16} />}
            tone="danger"
            confirm={`Delete ${g.GroupName}?`}
          />
        )
      }
    >
      <Specs
        items={[
          exposed > 0 && { label: "Exposed", icon: <ShieldAlert size={15} color="var(--bad)" />, value: <span style={{ color: "var(--bad)" }}>{exposed} open to the internet</span> },
          { label: "Inbound rules", icon: <ArrowDownLeft size={15} />, value: all.filter((r) => !r.IsEgress).length },
          { label: "Outbound rules", icon: <ArrowUpRight size={15} />, value: all.filter((r) => r.IsEgress).length },
          g.VpcId && { label: "VPC", icon: <Network size={15} />, value: <Link href={LINKS.vpc(g.VpcId)}>{(vpc && nameTag(vpc)) ?? g.VpcId}</Link> },
          { label: "Instances", icon: <Server size={15} />, value: instances.length },
        ]}
      />
      {g.Description && g.Description !== g.GroupName && <Facts items={[["Description", g.Description]]} />}
      <Segments
        label="Rules"
        items={[
          { label: "Inbound rules", href: here, active: direction === "ingress" },
          { label: "Outbound rules", href: `${here}&tab=outbound`, active: direction === "egress" },
          { label: "Tags", href: `${here}&tab=tags`, active: tab === "tags" },
        ]}
      />
      {tab === "tags" ? (
        <Section title="Tags" count={g.Tags?.length ?? 0} actions={<TagsSheet id={id} tags={g.Tags} />}>
          {g.Tags?.length ? <Tags tags={g.Tags} /> : <span className="muted">No tags</span>}
        </Section>
      ) : (
        <Section
          title={direction === "ingress" ? "Inbound rules" : "Outbound rules"}
          count={shown.length}
          plain
          actions={
            <Sheet title={`Add ${word} rule`} label={`Add ${word} rule`} icon={<Plus size={15} />} testId={`add-${word}-rule`}>
              <ActionForm action={addRule.bind(null, id, direction)} submit="Add rule" testId={`add-${word}-rule`}>
                <RuleFields direction={direction} peers={peers} vpc={g.VpcId} />
              </ActionForm>
            </Sheet>
          }
        >
          {rules.ok ? (
            <List
              label={direction === "ingress" ? "Inbound rules" : "Outbound rules"}
              empty={<Empty icon={ICONS.sg} />}
              rows={shown.map((d) => {
                const r = d.rule;
                const peerGroup = r.ReferencedGroupInfo?.GroupId;
                return {
                  key: r.SecurityGroupRuleId!,
                  icon: d.exposed ? <ShieldAlert size={18} color="var(--bad)" aria-label="Exposed to the internet" /> : direction === "ingress" ? <ArrowDownLeft size={18} aria-hidden /> : <ArrowUpRight size={18} aria-hidden />,
                  title: `${r.IpProtocol === "-1" ? "All traffic" : `${r.IpProtocol?.toUpperCase()} ${d.ports}`}`,
                  subtitle: (
                    <span>
                      {peerGroup ? (
                        <Link href={LINKS.group(peerGroup)}>{groupName(peerGroup)}</Link>
                      ) : (
                        <code>{d.source === "anywhere" ? d.peer : d.source}</code>
                      )}
                      {r.Description ? ` · ${r.Description}` : ""}
                    </span>
                  ),
                  meta: <code className="muted">{r.SecurityGroupRuleId}</code>,
                  actions: <ActionForm action={revokeRule.bind(null, id, direction, r.SecurityGroupRuleId!)} submit={`Remove ${d.text}`} icon={<X size={15} />} confirm={`Remove ${d.text}?`} />,
                };
              })}
            />
          ) : (
            <ErrorNotice error={rules.error} />
          )}
        </Section>
      )}
      {instances.length > 0 && tab !== "tags" && (
        <Section title="Instances" count={instances.length} plain>
          <List
            label="Instances using this group"
            rows={instances.map((i) => ({
              key: i.InstanceId!,
              icon: <AwsIcon icon={ICONS.instance} size={22} />,
              title: nameTag(i) ?? i.InstanceId,
              subtitle: [i.InstanceId, i.PrivateIpAddress].filter(Boolean).join(" · "),
              href: LINKS.instance(i.InstanceId!),
            }))}
          />
        </Section>
      )}
    </Page>
  );
}

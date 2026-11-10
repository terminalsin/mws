import "server-only";

import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Sheet } from "@mws-dashboard/ui";
import { ArrowUpRight, Plus, ShieldAlert, Trash2, X } from "lucide-react";
import Link from "next/link";

import { allowIngress, createSecurityGroup, deleteSecurityGroup, revokeIngress } from "../../routes/ec2/actions";
import { ICONS, LINKS, nameTag } from "../clients";
import { describeRule, listGroups, listRules, listVpcs } from "../ec2";
import { QuickRuleFields } from "../rule-fields";
import { MoreFields } from "@mws-dashboard/ui/presets";
import { GROUP_DESCRIPTION, GROUP_NAME, SOURCE_CIDR } from "../rules";

export async function GroupsView() {
  const [groups, rules, vpcs] = await Promise.all([load(() => listGroups()), load(() => listRules()), load(listVpcs)]);
  const vpcList = vpcs.ok ? vpcs.value : [];
  // Names in use in every VPC ("default") are taken whichever VPC is picked;
  // others are checked by EC2 per VPC.
  const vpcIds = vpcList.map((v) => v.VpcId);
  const groupList = groups.ok ? groups.value : [];
  const everywhere = [...new Set(groupList.map((g) => g.GroupName!))].filter((n) => vpcIds.every((v) => groupList.some((g) => g.GroupName === n && g.VpcId === v)));
  const defaultVpc = vpcList.find((v) => v.IsDefault)?.VpcId;
  const vpcName = (id?: string) => {
    const v = vpcList.find((x) => x.VpcId === id);
    return (v && nameTag(v)) ?? id;
  };
  const actions = (
    <Sheet title="New security group" label="Create security group" testId="create-security-group">
      <ActionForm action={createSecurityGroup} submit="Create" testId="create-security-group">
        <Field label="Name" rule={GROUP_NAME} member="GroupName" taken={everywhere} unique>
          <input name="name" required autoFocus />
        </Field>
        <MoreFields>
          <Field label="Description" rule={GROUP_DESCRIPTION} member="Description" hint="Blank: the name">
            <input name="description" />
          </Field>
          <Field label="VPC" member="VpcId">
            <select name="vpc" defaultValue={defaultVpc}>
              {vpcList.map((v) => (
                <option key={v.VpcId} value={v.VpcId}>
                  {nameTag(v) ?? v.VpcId}
                  {v.IsDefault ? " (default)" : ""}
                </option>
              ))}
            </select>
          </Field>
        </MoreFields>
      </ActionForm>
    </Sheet>
  );
  // "anywhere" or a VPC's name stand for their CIDR blocks.
  const cidrRule = {
    ...SOURCE_CIDR,
    aliases: {
      anywhere: "0.0.0.0/0",
      internet: "0.0.0.0/0",
      ...Object.fromEntries(vpcList.flatMap((v) => (v.CidrBlock ? [[nameTag(v) ?? v.VpcId!, v.CidrBlock]] : []))),
    },
  };
  const ruleList = rules.ok ? rules.value : [];
  const body = groups.ok ? (
    <>
      {!rules.ok && <ErrorNotice error={rules.error} />}
      <List
        label="Security groups"
        empty={<Empty icon={ICONS.sg} />}
        rows={groups.value.map((g) => {
          const mine = ruleList.filter((r) => r.GroupId === g.GroupId);
          const described = mine.filter((r) => !r.IsEgress).map((r) => ({ rule: r, ...describeRule(r) }));
          const outbound = mine.filter((r) => r.IsEgress).length;
          const exposed = described.filter((d) => d.exposed);
          return {
            key: g.GroupId!,
            icon: exposed.length ? <ShieldAlert size={20} color="var(--bad)" aria-label="Exposed to the internet" /> : <AwsIcon icon={ICONS.sg} size={22} />,
            title: <Link href={LINKS.group(g.GroupId!)}>{g.GroupName}</Link>,
            subtitle: (
              <span className="chips">
                {described.map((d) => (
                  <span key={d.rule.SecurityGroupRuleId} className={d.exposed ? "chip bad" : "chip"} title={d.rule.Description}>
                    {d.ports} ← {d.source}
                    <ActionForm action={revokeIngress.bind(null, g.GroupId!, d.rule.SecurityGroupRuleId!)} submit={`Remove ${d.text}`} icon={<X size={11} />} />
                  </span>
                ))}
              </span>
            ),
            meta: (
              <>
                <span title="Outbound rules" style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                  <ArrowUpRight size={13} aria-label="Outbound rules" /> {outbound}
                </span>
                {g.VpcId && (
                  <Link href={LINKS.vpc(g.VpcId)} className="muted">
                    {vpcName(g.VpcId)}
                  </Link>
                )}
              </>
            ),
            actions: (
              <>
                <Sheet title={`Allow inbound · ${g.GroupName}`} label={`Allow inbound to ${g.GroupName}`} icon={<Plus size={15} />}>
                  <ActionForm action={allowIngress.bind(null, g.GroupId!)} submit="Allow">
                    <QuickRuleFields cidrRule={cidrRule} />
                  </ActionForm>
                </Sheet>
                {g.GroupName !== "default" && (
                  <ActionForm action={deleteSecurityGroup.bind(null, g.GroupId!)} submit={`Delete ${g.GroupName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${g.GroupName}?`} />
                )}
              </>
            ),
          };
        })}
      />
    </>
  ) : (
    <ErrorNotice error={groups.error} />
  );
  return { body, actions };
}

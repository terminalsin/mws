import { GetIPSetCommand, GetThreatIntelSetCommand, ListIPSetsCommand, ListThreatIntelSetsCommand } from "@aws-sdk/client-guardduty";
import { all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Page, Pill, Sheet, Status, type Rule } from "@mws-dashboard/ui";
import { CreateIPSet } from "@mws-dashboard/ui/model/guardduty";
import { MoreFields } from "@mws-dashboard/ui/presets";
import { Pause, Play, ShieldAlert, ShieldCheck, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, detectorId, guardduty, s3Objects } from "../../../lib/clients";
import { GuardDutyNav } from "../../../lib/nav";
import { createList, deleteList, enableGuardDuty, setListActive, type ListKind } from "../actions";

export const metadata: Metadata = { title: "Lists · GuardDuty" };

const NAME: Rule = { ...CreateIPSet.Name, generate: "name" };
const FORMATS: [string, string][] = [
  ["TXT", "Plaintext"],
  ["STIX", "STIX"],
  ["OTX_CSV", "Open Threat Exchange CSV"],
  ["ALIEN_VAULT", "AlienVault"],
  ["PROOF_POINT", "Proofpoint ET"],
  ["FIRE_EYE", "FireEye iSIGHT"],
];

interface List {
  kind: ListKind;
  id: string;
  name: string;
  location: string;
  format: string;
  active: boolean;
}

function AddList({ detector, kind, names, objects }: { detector: string; kind: ListKind; names: string[]; objects: string[] }) {
  const trusted = kind === "trusted";
  return (
    <Sheet title={trusted ? "Trusted IP list" : "Threat list"} label={trusted ? "Add trusted IP list" : "Add threat list"} icon={trusted ? <ShieldCheck size={16} /> : <ShieldAlert size={16} />} testId={`add-${kind}`}>
      <ActionForm action={createList.bind(null, detector, kind)} submit="Add" testId={`add-${kind}`}>
        <Field label="Name" rule={NAME} taken={names} unique>
          <input name="name" required autoFocus />
        </Field>
        <Field label="Location" rule={CreateIPSet.Location} format="s3url" known={objects}>
          <input name="location" required placeholder="s3://bucket/key" />
        </Field>
        <MoreFields>
          <Field label="Format" rule={CreateIPSet.Format}>
            <select name="format" defaultValue="TXT">
              {FORMATS.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </Field>
          <label className="check">
            <input type="checkbox" name="activate" defaultChecked /> Activate
          </label>
        </MoreFields>
      </ActionForm>
    </Sheet>
  );
}

export default async function Lists() {
  const data = await load(async () => {
    const detector = await detectorId();
    if (!detector) return undefined;
    const client = await guardduty();
    const [ipSets, threatSets, objects] = await Promise.all([
      all(
        (NextToken) => client.send(new ListIPSetsCommand({ DetectorId: detector, NextToken })),
        (r) => r.IpSetIds,
        (r) => r.NextToken,
      ),
      all(
        (NextToken) => client.send(new ListThreatIntelSetsCommand({ DetectorId: detector, NextToken })),
        (r) => r.ThreatIntelSetIds,
        (r) => r.NextToken,
      ),
      s3Objects(),
    ]);
    const lists: List[] = await Promise.all([
      ...ipSets.map(async (id) => {
        const l = await client.send(new GetIPSetCommand({ DetectorId: detector, IpSetId: id }));
        return { kind: "trusted" as const, id, name: l.Name!, location: l.Location!, format: l.Format!, active: l.Status === "ACTIVE" };
      }),
      ...threatSets.map(async (id) => {
        const l = await client.send(new GetThreatIntelSetCommand({ DetectorId: detector, ThreatIntelSetId: id }));
        return { kind: "threat" as const, id, name: l.Name!, location: l.Location!, format: l.Format!, active: l.Status === "ACTIVE" };
      }),
    ]);
    return { detector, lists, objects };
  });
  if (!data.ok) {
    return (
      <Page title="Lists">
        <GuardDutyNav active="lists" />
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  if (!data.value) {
    return (
      <Page title="Lists">
        <Empty icon={ICONS.guardduty} action={<ActionForm action={enableGuardDuty} submit="Enable GuardDuty" testId="enable-guardduty" />} />
      </Page>
    );
  }
  const { detector, lists, objects } = data.value;
  const of = (kind: ListKind) => lists.filter((l) => l.kind === kind);
  return (
    <Page
      title="Lists"
      actions={
        <>
          {/* One trusted IP list per detector. */}
          {of("trusted").length === 0 && <AddList detector={detector} kind="trusted" names={[]} objects={objects} />}
          <AddList detector={detector} kind="threat" names={of("threat").map((l) => l.name)} objects={objects} />
        </>
      }
    >
      <GuardDutyNav active="lists" />
      <Curated
        label="Lists"
        sections={[
          { id: "trusted", title: "Trusted IP lists", items: of("trusted") },
          { id: "threat", title: "Threat lists", items: of("threat") },
        ]}
        empty={<Empty icon={ICONS.guardduty} />}
        row={(l) => ({
          key: l.id,
          icon: <AwsIcon icon={l.kind === "trusted" ? "resource/Shield" : "resource/Alert"} size={22} />,
          title: l.name,
          subtitle: l.location,
          meta: (
            <>
              <Status tone={l.active ? "good" : "neutral"}>{l.active ? "Active" : "Inactive"}</Status>
              {l.format !== "TXT" && <Pill>{FORMATS.find(([v]) => v === l.format)?.[1] ?? l.format}</Pill>}
            </>
          ),
          actions: (
            <>
              <ActionForm action={setListActive.bind(null, detector, l.kind, l.id, !l.active)} submit={l.active ? "Deactivate" : "Activate"} icon={l.active ? <Pause size={15} /> : <Play size={15} />} />
              <ActionForm action={deleteList.bind(null, detector, l.kind, l.id)} submit="Delete list" icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${l.name}?`} />
            </>
          ),
        })}
      />
    </Page>
  );
}

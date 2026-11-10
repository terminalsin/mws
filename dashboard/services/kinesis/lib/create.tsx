"use client";

// The create-stream form: pick the capacity (on-demand scales itself; a
// provisioned size names its shards), and the name follows.

import type { Rule } from "@mws-dashboard/ui";
import { FieldShell } from "@mws-dashboard/ui/fields";
import { CreateStream } from "@mws-dashboard/ui/model/kinesis";
import { freeName, MoreFields, PresetGallery } from "@mws-dashboard/ui/presets";
import { Infinity as Unlimited, Layers, Layers2, Layers3 } from "lucide-react";
import { useState, type ReactNode } from "react";

interface Capacity {
  id: string;
  label: string;
  title: string;
  icon: ReactNode;
  mode: "ON_DEMAND" | "PROVISIONED";
  shards?: number;
}

const CAPACITY: Capacity[] = [
  { id: "on-demand", label: "On-demand", title: "Scales with traffic; up to 200 MB/s writes", icon: <Unlimited size={26} aria-hidden />, mode: "ON_DEMAND" },
  { id: "provisioned", label: "1 shard", title: "Provisioned: 1 MB/s or 1,000 records/s in", icon: <Layers2 size={26} aria-hidden />, mode: "PROVISIONED", shards: 1 },
  { id: "provisioned-4", label: "4 shards", title: "Provisioned: 4 MB/s in", icon: <Layers3 size={26} aria-hidden />, mode: "PROVISIONED", shards: 4 },
  { id: "provisioned-custom", label: "Custom", title: "Provisioned, any number of shards", icon: <Layers size={26} aria-hidden />, mode: "PROVISIONED" },
];

export const STREAM_NAME: Rule = { ...CreateStream.StreamName, hint: "Letters, digits, _ . -", generate: "name" };

export function CreateStreamFields({ names }: { names: string[] }) {
  const [cap, setCap] = useState(CAPACITY[0]);
  return (
    <>
      <PresetGallery presets={CAPACITY} chosen={cap.id} choose={setCap} label="Capacity" testId="capacity" />
      <input type="hidden" name="mode" value={cap.mode} />
      <FieldShell label="Name" rule={STREAM_NAME} taken={names} unique>
        <input name="name" required defaultValue={freeName("stream", names)} spellCheck={false} />
      </FieldShell>
      <div key={cap.id}>
        {cap.mode === "PROVISIONED" && (
          <FieldShell label="Shards" rule={CreateStream.ShardCount}>
            <input name="shards" type="number" min={1} defaultValue={cap.shards ?? 2} />
          </FieldShell>
        )}
      </div>
      <MoreFields label="Tags">
        <FieldShell label="Tags" rule={{ ...CreateStream.Tags, format: "tags" }}>
          <textarea name="tags" rows={1} placeholder="team=data" />
        </FieldShell>
      </MoreFields>
    </>
  );
}

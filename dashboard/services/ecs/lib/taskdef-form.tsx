"use client";

// The new task definition form opens on images: picking one fills in the
// family, image, port and size; command, environment and logs wait under More.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { RegisterTaskDefinition } from "@mws-dashboard/ui/model/ecs";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import { Section, Sections } from "@mws-dashboard/ui/sections";
import { useState } from "react";

import { IMAGE_PRESETS, type ImagePreset } from "./presets";
import { IMAGE, NAME } from "./rules";
import { FargateSize } from "./size.tsx";

export function TaskDefinitionFields({ families }: { families: string[] }) {
  const [preset, setPreset] = useState<ImagePreset>(IMAGE_PRESETS[0]);
  const custom = preset.id === "custom";
  const items = IMAGE_PRESETS.map((p) => ({ ...p, title: p.image || "Any image", added: families.includes(p.id) }));
  return (
    <Sections testId="taskdef">
      <Section id="image" label="Image" summary={preset.label}>
        <PresetGallery presets={items} chosen={preset.id} choose={(p) => setPreset(IMAGE_PRESETS.find((x) => x.id === p.id)!)} label="Image" size={26} />
        <div key={preset.id} className="preset-fields">
          <FieldShell label="Image URI" rule={IMAGE}>
            <input name="image" required defaultValue={preset.image} placeholder="public.ecr.aws/nginx/nginx:latest" />
          </FieldShell>
        </div>
      </Section>
      <Section id="container" label="Container">
        <div key={preset.id} className="preset-fields">
          <FieldShell label="Family" rule={{ ...RegisterTaskDefinition.family, ...NAME }} known={families}>
            <input name="family" required defaultValue={custom ? undefined : freeName(preset.id, families)} />
          </FieldShell>
          <FargateSize cpu={preset.cpu} memory={preset.memory} />
          <FieldShell label="Port" format="port">
            <input name="port" type="number" min={1} max={65535} defaultValue={preset.port} placeholder="80" />
          </FieldShell>
          <MoreFields expanded={!!preset.env}>
            <FieldShell label="Command">
              <input name="command" defaultValue={preset.command} />
            </FieldShell>
            <FieldShell label="Environment" format="env">
              <textarea name="env" rows={3} spellCheck={false} defaultValue={preset.env} placeholder="KEY=value" />
            </FieldShell>
            <label className="check">
              <input type="checkbox" name="logs" defaultChecked /> Send output to CloudWatch Logs
            </label>
          </MoreFields>
        </div>
      </Section>
    </Sections>
  );
}

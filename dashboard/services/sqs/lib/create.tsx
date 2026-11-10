"use client";

// The create-queue form: a gallery of queue kinds, each filling its
// defaults; timings and redrive/encryption settings wait under More.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { freeName, MoreFields, PresetGallery } from "@mws-dashboard/ui/presets";
import { Hourglass, ListOrdered, Skull, Timer } from "lucide-react";
import { useState, type ReactNode } from "react";

import { QUEUE_PRESETS, type QueuePreset } from "./presets";
import { ATTRIBUTE_RULES as RULES, KMS_KEY, KMS_REUSE, MAX_RECEIVES, QUEUE_NAME, SOURCE_ARNS } from "./rules";
import { QueueSettings } from "./settings";

const ICON: Record<string, string | ReactNode> = {
  standard: "resource/AmazonSimpleQueueServiceQueue",
  fifo: <ListOrdered size={26} aria-hidden />,
  "long-poll": <Hourglass size={26} aria-hidden />,
  delay: <Timer size={26} aria-hidden />,
  dlq: <Skull size={26} aria-hidden />,
};

export function CreateQueueFields({ queues }: { queues: { name: string; arn: string; fifo: boolean }[] }) {
  const [preset, setPreset] = useState<QueuePreset>(QUEUE_PRESETS[0]);
  const names = queues.map((q) => q.name);
  const suggested = preset.fifo ? `${freeName(preset.name.replace(/\.fifo$/, ""), names.filter((n) => n.endsWith(".fifo")).map((n) => n.slice(0, -5)))}.fifo` : freeName(preset.name, names);
  return (
    <>
      <PresetGallery presets={QUEUE_PRESETS.map((p) => ({ ...p, icon: ICON[p.id] }))} chosen={preset.id} choose={setPreset} label="Queue type" testId="queue-preset" />
      <div key={preset.id}>
        <FieldShell label="Name" rule={QUEUE_NAME} taken={names} unique>
          <input name="name" required maxLength={80} defaultValue={suggested} spellCheck={false} />
        </FieldShell>
        {preset.fifo && <input type="hidden" name="fifo" value="on" />}
        <MoreFields>
          <div className="form-row">
            <FieldShell label="Visibility timeout (s)" rule={RULES.VisibilityTimeout}>
              <input name="VisibilityTimeout" inputMode="numeric" placeholder="30" defaultValue={preset.VisibilityTimeout} />
            </FieldShell>
            <FieldShell label="Retention (s)" rule={RULES.MessageRetentionPeriod}>
              <input name="MessageRetentionPeriod" inputMode="numeric" placeholder="345600" defaultValue={preset.MessageRetentionPeriod} />
            </FieldShell>
            <FieldShell label="Delay (s)" rule={RULES.DelaySeconds}>
              <input name="DelaySeconds" inputMode="numeric" placeholder="0" defaultValue={preset.DelaySeconds} />
            </FieldShell>
            <FieldShell label="Receive wait (s)" rule={RULES.ReceiveMessageWaitTimeSeconds}>
              <input name="ReceiveMessageWaitTimeSeconds" inputMode="numeric" placeholder="0" defaultValue={preset.ReceiveMessageWaitTimeSeconds} />
            </FieldShell>
          </div>
          <QueueSettings
            queues={queues}
            fifo={preset.fifo}
            current={{ dedup: preset.dedup, allow: preset.allow }}
            rules={{ maxReceives: MAX_RECEIVES, kmsKey: KMS_KEY, kmsReuse: KMS_REUSE, sources: SOURCE_ARNS }}
          />
        </MoreFields>
      </div>
    </>
  );
}

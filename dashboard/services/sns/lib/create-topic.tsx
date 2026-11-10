"use client";

// The create-topic form: a gallery of common topic kinds, each naming the
// topic (uniquely) and setting what it needs.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { freeName, MoreFields, PresetGallery } from "@mws-dashboard/ui/presets";
import { BellRing, ListOrdered } from "lucide-react";
import { useState, type ReactNode } from "react";

import { DISPLAY_NAME, TOPIC_NAME } from "./rules";

interface TopicPreset {
  id: string;
  label: string;
  title: string;
  icon: string | ReactNode;
  name: string;
  displayName?: string;
  fifo?: boolean;
}

const PRESETS: TopicPreset[] = [
  { id: "standard", label: "Standard", title: "Best-effort ordering, any protocol", icon: "resource/AmazonSimpleNotificationServiceTopic", name: "topic" },
  { id: "fifo", label: "FIFO", title: "Ordered, deduplicated; delivers to SQS and Firehose", icon: <ListOrdered size={26} aria-hidden />, name: "events", fifo: true },
  { id: "alerts", label: "Alerts", title: "For CloudWatch alarms and on-call email/SMS", icon: <BellRing size={26} aria-hidden />, name: "alerts", displayName: "Alerts" },
  { id: "email", label: "Email digest", title: "Notifications people subscribe to by email", icon: "resource/AmazonSimpleNotificationServiceEmailNotification", name: "notifications", displayName: "Notifications" },
];

export function CreateTopicFields({ names }: { names: string[] }) {
  const [preset, setPreset] = useState(PRESETS[0]);
  const name = preset.fifo ? `${freeName(preset.name, names.filter((n) => n.endsWith(".fifo")).map((n) => n.slice(0, -5)))}.fifo` : freeName(preset.name, names);
  return (
    <>
      <PresetGallery presets={PRESETS} chosen={preset.id} choose={setPreset} label="Topic type" testId="topic-preset" />
      <div key={preset.id}>
        <FieldShell label="Name" rule={TOPIC_NAME} taken={names} unique>
          <input name="name" required maxLength={256} defaultValue={name} spellCheck={false} />
        </FieldShell>
        {preset.fifo ? (
          <>
            <input type="hidden" name="fifo" value="on" />
            <label className="check">
              <input type="checkbox" name="dedup" defaultChecked /> Content-based deduplication
            </label>
          </>
        ) : null}
        {preset.displayName ? (
          <FieldShell label="Display name" rule={DISPLAY_NAME} member="DisplayName">
            <input name="displayName" defaultValue={preset.displayName} />
          </FieldShell>
        ) : (
          <MoreFields>
            <FieldShell label="Display name" rule={DISPLAY_NAME} member="DisplayName">
              <input name="displayName" />
            </FieldShell>
          </MoreFields>
        )}
      </div>
    </>
  );
}

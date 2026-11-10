"use client";

import { PresetGallery } from "@mws-dashboard/ui/presets";
import { Globe } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";

/** Where a stream delivers: the console's three kinds, and partners that
 * take Firehose's HTTP endpoint protocol (with their intake URL filled). */
interface Dest {
  id: string;
  label: string;
  icon: string | ReactNode;
  group?: string;
  kind: "s3" | "http" | "splunk";
  url?: string;
  placeholder?: string;
  endpointName?: string;
}

const DESTINATIONS: Dest[] = [
  { id: "s3", label: "Amazon S3", icon: "service/AmazonSimpleStorageService", kind: "s3" },
  { id: "http", label: "HTTP endpoint", icon: <Globe size={26} aria-hidden />, kind: "http" },
  { id: "splunk", label: "Splunk", icon: "brand/splunk", kind: "splunk" },
  { id: "datadog", label: "Datadog", icon: "brand/datadog", group: "Partners", kind: "http", url: "https://aws-kinesis-http-intake.logs.datadoghq.com/v1/input", endpointName: "Datadog" },
  { id: "newrelic", label: "New Relic", icon: "brand/newrelic", group: "Partners", kind: "http", url: "https://aws-api.newrelic.com/firehose/v1", endpointName: "New Relic" },
  { id: "elastic", label: "Elastic", icon: "brand/elastic", group: "Partners", kind: "http", placeholder: "https://<deployment>.es.<region>.aws.elastic-cloud.com", endpointName: "Elastic" },
];

/** The destination picker: a logo per destination, and only the chosen
 * kind's fieldsets (`data-dest`) shown; hidden ones are disabled so they
 * are neither validated nor sent. A partner fills its endpoint. */
export function DestinationSwitch({ name, children }: { name: string; children: ReactNode }) {
  const box = useRef<HTMLDivElement>(null);
  const [dest, setDest] = useState(DESTINATIONS[0]);
  useEffect(() => {
    const root = box.current;
    if (!root) return;
    for (const set of root.querySelectorAll<HTMLFieldSetElement>("fieldset[data-dest]")) {
      const on = set.dataset.dest!.split(" ").includes(dest.kind);
      set.hidden = !on;
      set.disabled = !on;
    }
  }, [dest]);
  const choose = (d: Dest) => {
    setDest(d);
    const form = box.current?.closest("form");
    if (!form || d.kind !== "http") return;
    const set = (field: string, value: string | undefined, placeholder?: string) => {
      const el = form.elements.namedItem(field) as HTMLInputElement | null;
      if (!el) return;
      el.value = value ?? "";
      if (placeholder !== undefined) el.placeholder = placeholder;
    };
    set("url", d.url, d.placeholder ?? "https://example.com/ingest");
    set("endpointName", d.endpointName);
  };
  return (
    <div ref={box}>
      <PresetGallery presets={DESTINATIONS} chosen={dest.id} choose={choose} label="Destination" testId="destination" />
      <input type="hidden" name={name} value={dest.kind} />
      {children}
    </div>
  );
}

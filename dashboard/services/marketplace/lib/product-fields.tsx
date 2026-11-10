"use client";

// The create-product fields: the sheet opens on the product type, which
// fills in a title and the pricing dimension that type usually meters.

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { freeName, MoreFields, PresetGallery } from "@mws-dashboard/ui/presets";
import { useState } from "react";

import { ACCOUNT, DIMENSIONS, TITLE } from "./rules";

const TYPES = [
  { id: "SaaS", label: "SaaS", icon: "service/AWSMarketplace", title: "Software billed per user or request", name: "My SaaS", dimensions: "users" },
  { id: "AMI", label: "AMI", icon: "resource/AmazonEC2AMI", title: "A machine image billed per instance hour", name: "My AMI", dimensions: "hours" },
  { id: "Container", label: "Container", icon: "service/AmazonElasticContainerService", title: "A container product billed per task", name: "My container", dimensions: "tasks" },
];

export function ProductFields({ titles, codes }: { titles: string[]; codes: string[] }) {
  const [type, setType] = useState(TYPES[0]);
  return (
    <>
      <PresetGallery label="Type" presets={TYPES} chosen={type.id} choose={(p) => setType(TYPES.find((t) => t.id === p.id)!)} />
      <input type="hidden" name="type" value={type.id} />
      <div key={type.id}>
        <Field label="Title" rule={TITLE}>
          <input name="title" required defaultValue={freeName(type.name, titles)} />
        </Field>
        <Field label="Pricing dimensions" rule={DIMENSIONS}>
          <input name="dimensions" required defaultValue={type.dimensions} placeholder="users, requests" />
        </Field>
        <MoreFields>
          <div className="form-row">
            <Field label="Product code" hint="Generated when empty" taken={codes} unique>
              <input name="code" pattern="[A-Za-z0-9]{1,255}" />
            </Field>
            <Field label="Seller account" rule={{ ...ACCOUNT, required: false, generate: undefined }} hint="This account when empty">
              <input name="seller" inputMode="numeric" />
            </Field>
          </div>
        </MoreFields>
      </div>
    </>
  );
}

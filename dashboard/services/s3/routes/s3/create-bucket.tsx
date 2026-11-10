"use client";

import { ActionForm, Field } from "@mws-dashboard/ui";
import { CreateBucket as CreateBucketRules } from "@mws-dashboard/ui/model/s3";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import { useState } from "react";

import { BUCKET_PRESETS, type BucketPreset } from "../../lib/presets";
import { createBucket } from "./actions";

/** The create sheet's form: it opens on what the bucket is for, which
 * suggests a free name and turns on versioning or Object Lock where that
 * job wants them. One click and Create covers the common case. */
export function CreateBucketForm({ names }: { names: string[] }) {
  const [preset, setPreset] = useState<BucketPreset>(BUCKET_PRESETS[0]);
  return (
    <ActionForm action={createBucket} submit="Create" testId="create-bucket">
      <PresetGallery presets={BUCKET_PRESETS} chosen={preset.id} choose={setPreset} label="Purpose" />
      <div key={preset.id} className="preset-fields">
        <Field label="Name" rule={CreateBucketRules.Bucket} format="bucket" generate="name" taken={names} unique>
          <input name="name" required minLength={3} maxLength={63} defaultValue={freeName(preset.name, names)} />
        </Field>
        <div className="form-row">
          <label className="check">
            <input type="checkbox" name="versioning" defaultChecked={!!preset.versioning || !!preset.lock} /> Versioning
          </label>
          <label className="check">
            <input type="checkbox" name="lock" defaultChecked={!!preset.lock} /> Object Lock
          </label>
        </div>
        <MoreFields>
          <Field label="Object Ownership" rule={CreateBucketRules.ObjectOwnership}>
            <select name="ownership" defaultValue="BucketOwnerEnforced">
              <option value="BucketOwnerEnforced">ACLs disabled (bucket owner enforced)</option>
              <option value="BucketOwnerPreferred">ACLs enabled, bucket owner preferred</option>
              <option value="ObjectWriter">ACLs enabled, object writer</option>
            </select>
          </Field>
        </MoreFields>
      </div>
    </ActionForm>
  );
}

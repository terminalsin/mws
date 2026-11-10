"use client";

// "Create file system" opens on the storage class, as AWS's quick create
// does: Regional or One Zone (which then asks for its zone). Name and VPC
// are all most file systems need; performance, throughput, lifecycle and
// encryption keep their defaults under More.

import type { Rule } from "@mws-dashboard/ui";
import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { CreateFileSystem as Rules } from "@mws-dashboard/ui/model/efs";
import { MoreFields, PresetGallery } from "@mws-dashboard/ui/presets";
import { useState } from "react";

import { IA_OPTIONS } from "./options";

const CLASSES = [
  { id: "regional", label: "Regional", icon: "resource/AmazonElasticFileSystemEFSStandard", title: "Stored across Availability Zones" },
  { id: "one-zone", label: "One Zone", icon: "resource/AmazonElasticFileSystemEFSOneZone", title: "Stored in one Availability Zone, for less" },
];

export function CreateFileSystemFields({ nameRule, vpcs, defaultVpc, zones }: { nameRule: Rule; vpcs: { id: string; label: string }[]; defaultVpc?: string; zones: string[] }) {
  const [storage, setStorage] = useState(CLASSES[0]);
  const [throughput, setThroughput] = useState("elastic");
  return (
    <>
      <PresetGallery presets={zones.length ? CLASSES : CLASSES.slice(0, 1)} chosen={storage.id} choose={setStorage} label="Storage" testId="storage" />
      <Field label="Name" rule={nameRule} member="Tags.Value">
        <input name="name" autoFocus />
      </Field>
      <div className="form-row">
        <Field label="VPC" member="SubnetId" hint="A mount target in each Availability Zone">
          <select name="vpc" defaultValue={defaultVpc ?? ""}>
            <option value="">No mount targets</option>
            {vpcs.map((v) => (
              <option key={v.id} value={v.id}>
                {v.label}
              </option>
            ))}
          </select>
        </Field>
        {storage.id === "one-zone" ? (
          <Field label="Availability Zone" rule={Rules.AvailabilityZoneName} member="AvailabilityZoneName">
            <select name="az" defaultValue={zones[0]}>
              {zones.map((z) => (
                <option key={z}>{z}</option>
              ))}
            </select>
          </Field>
        ) : (
          <input type="hidden" name="az" value="" />
        )}
      </div>
      <MoreFields>
        <div className="form-row">
          <Field label="Performance" rule={Rules.PerformanceMode}>
            <select name="performance" defaultValue="generalPurpose">
              <option value="generalPurpose">General Purpose</option>
              <option value="maxIO">Max I/O</option>
            </select>
          </Field>
          <Field label="Throughput" rule={Rules.ThroughputMode}>
            <select name="throughput" value={throughput} onChange={(e) => setThroughput(e.target.value)}>
              <option value="elastic">Elastic</option>
              <option value="bursting">Bursting</option>
              <option value="provisioned">Provisioned</option>
            </select>
          </Field>
          {throughput === "provisioned" && (
            <Field label="Provisioned MiB/s" rule={Rules.ProvisionedThroughputInMibps}>
              <input name="mibps" type="number" min={1} step="any" required />
            </Field>
          )}
        </div>
        <div className="form-row">
          <Field label="Transition to Infrequent Access" member="LifecyclePolicies">
            <select name="ia" defaultValue="AFTER_30_DAYS">
              <option value="">None</option>
              {IA_OPTIONS.map(([v, l]) => (
                <option key={v} value={v}>
                  {l}
                </option>
              ))}
            </select>
          </Field>
          <Field label="KMS key" rule={Rules.KmsKeyId} hint="Empty uses aws/elasticfilesystem">
            <input name="kms" />
          </Field>
        </div>
        <label className="check">
          <input type="checkbox" name="encrypted" defaultChecked /> Encrypted
        </label>
        <label className="check">
          <input type="checkbox" name="backup" defaultChecked /> Automatic backups
        </label>
      </MoreFields>
    </>
  );
}

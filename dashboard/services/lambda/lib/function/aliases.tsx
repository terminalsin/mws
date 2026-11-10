import type { AliasConfiguration, FunctionConfiguration } from "@aws-sdk/client-lambda";
import { ago } from "@mws-dashboard/aws";
import { ActionForm, Empty, Field, List, Pill, Section, Sheet } from "@mws-dashboard/ui";
import { GitBranch, GitCommitVertical, Play, Settings2, Trash2 } from "lucide-react";
import Link from "next/link";

import { createAlias, deleteAlias, updateAlias } from "../../routes/lambda/actions";
import { ALIAS_DESCRIPTION, ALIAS_NAME, WEIGHT } from "../rules";

function AliasFields({ versions, alias }: { versions: string[]; alias?: AliasConfiguration }) {
  const [extra, weight] = Object.entries(alias?.RoutingConfig?.AdditionalVersionWeights ?? {})[0] ?? [];
  return (
    <>
      <div className="form-row">
        <Field label="Version">
          <select name="version" defaultValue={alias?.FunctionVersion ?? versions[versions.length - 1]} required>
            {["$LATEST", ...versions].map((v) => (
              <option key={v}>{v}</option>
            ))}
          </select>
        </Field>
        <Field label="Description" rule={ALIAS_DESCRIPTION}>
          <input name="description" defaultValue={alias?.Description} />
        </Field>
      </div>
      {versions.length > 1 && (
        <div className="form-row">
          <Field label="Weighted: additional version">
            <select name="extraVersion" defaultValue={extra ?? ""}>
              <option value="">None</option>
              {versions.map((v) => (
                <option key={v}>{v}</option>
              ))}
            </select>
          </Field>
          <Field label="Weight (%)" rule={WEIGHT}>
            <input name="weight" inputMode="numeric" defaultValue={weight !== undefined ? Math.round(weight * 100) : undefined} />
          </Field>
        </div>
      )}
    </>
  );
}

export function Aliases({ name, base, aliases, versions }: { name: string; base: string; aliases: AliasConfiguration[]; versions: string[] }) {
  return (
    <Section
      title="Aliases"
      count={aliases.length}
      plain
      actions={
        <Sheet title="Create alias" label="Create alias" testId="create-alias">
          <ActionForm action={createAlias.bind(null, name)} submit="Create" testId="create-alias">
            <Field label="Name" rule={ALIAS_NAME} taken={aliases.map((a) => a.Name!)} unique member="Name">
              <input name="alias" required autoFocus spellCheck={false} />
            </Field>
            <AliasFields versions={versions} />
          </ActionForm>
        </Sheet>
      }
    >
      <List
        label="Aliases"
        empty={<Empty icon="resource/AWSLambdaLambdaFunction" />}
        rows={aliases.map((a) => {
          const weights = Object.entries(a.RoutingConfig?.AdditionalVersionWeights ?? {});
          return {
            key: a.Name!,
            icon: <GitBranch size={18} aria-hidden />,
            title: a.Name,
            subtitle: a.Description,
            meta: (
              <>
                <Pill title="Version">{a.FunctionVersion}</Pill>
                {weights.map(([v, w]) => (
                  <Pill key={v} tone="info" title="Weighted routing">
                    {v} · {Math.round(w * 100)}%
                  </Pill>
                ))}
              </>
            ),
            actions: (
              <>
                <Link className="icon-button plain" href={`${base}?tab=test&qualifier=${encodeURIComponent(a.Name!)}`} aria-label={`Test ${a.Name}`} title="Test">
                  <Play size={15} aria-hidden />
                </Link>
                <Sheet title={`Alias ${a.Name}`} label={`Edit ${a.Name}`} icon={<Settings2 size={15} aria-hidden />} testId="edit-alias">
                  <ActionForm action={updateAlias.bind(null, name, a.Name!)} submit="Save" testId="edit-alias">
                    <AliasFields versions={versions} alias={a} />
                  </ActionForm>
                </Sheet>
                <ActionForm action={deleteAlias.bind(null, name, a.Name!)} submit={`Delete ${a.Name}`} icon={<Trash2 size={15} aria-hidden />} tone="danger" confirm={`Delete alias ${a.Name}?`} />
              </>
            ),
          };
        })}
      />
    </Section>
  );
}

export function Versions({ base, versions, aliases }: { base: string; versions: FunctionConfiguration[]; aliases: AliasConfiguration[] }) {
  return (
    <Section
      title="Versions"
      count={versions.length}
      plain
    >
      <List
        label="Versions"
        empty={<Empty icon="resource/AWSLambdaLambdaFunction" />}
        rows={[...versions].reverse().map((v) => {
          const pointing = aliases.filter((a) => a.FunctionVersion === v.Version || v.Version! in (a.RoutingConfig?.AdditionalVersionWeights ?? {}));
          return {
            key: v.Version!,
            icon: <GitCommitVertical size={18} aria-hidden />,
            title: v.Version,
            subtitle: v.Description,
            href: `${base}?tab=test&qualifier=${encodeURIComponent(v.Version!)}`,
            meta: (
              <>
                {pointing.map((a) => (
                  <Pill key={a.Name} tone="info">
                    {a.Name}
                  </Pill>
                ))}
                {v.Runtime && <Pill>{v.Runtime}</Pill>}
                <span>{ago(v.LastModified)}</span>
              </>
            ),
          };
        })}
      />
    </Section>
  );
}

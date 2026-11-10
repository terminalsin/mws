"use client";

// Preset galleries, the pattern the Bedrock provider sheet started: a form
// opens on a grid of logos, picking one fills in sensible values and shows
// only the fields that choice needs. The rest wait under More.
//
//   const [p, setP] = useState(PRESETS[0]);
//   <PresetGallery presets={PRESETS} chosen={p.id} choose={setP} label="Runtime" />
//   <div key={p.id}> ...fields with defaultValue={p.values.x}... </div>
//   <MoreFields> ...rarely needed fields... </MoreFields>

import { Check, SlidersHorizontal } from "lucide-react";
import type { ReactNode } from "react";

import { iconUrl } from "./catalog";

export interface PresetItem {
  id: string;
  label: string;
  /** An icon id ("service/...", "resource/...", "brand/...", "ai/...") or a node (a lucide icon). */
  icon: string | ReactNode;
  /** Section heading; presets without one go in an unnamed first group. */
  group?: string;
  /** Shown as the button's tooltip. */
  title?: string;
  /** A green dot: available / detected / recommended. */
  found?: boolean;
  /** A check: one already exists. */
  added?: boolean;
  disabled?: boolean;
}

function Logo({ icon, size }: { icon: string | ReactNode; size: number }) {
  if (typeof icon !== "string") return <>{icon}</>;
  if (!icon) return null;
  return <img src={iconUrl(icon)} alt="" width={size} height={size} style={{ width: size, height: size }} />;
}

/** A radio group of logo tiles. Groups keep the order they first appear in. */
export function PresetGallery<P extends PresetItem>({
  presets,
  chosen,
  choose,
  label,
  size = 28,
  testId = "preset",
}: {
  presets: P[];
  chosen: string | undefined;
  choose: (p: P) => void;
  label: string;
  size?: number;
  testId?: string;
}) {
  const groups = new Map<string, P[]>();
  for (const p of presets) {
    const g = p.group ?? "";
    groups.set(g, [...(groups.get(g) ?? []), p]);
  }
  return (
    <div className="presets" role="radiogroup" aria-label={label}>
      {[...groups].map(([title, list]) => (
        <section key={title || "_"} aria-label={title || label}>
          {title && <h3>{title}</h3>}
          <div className="preset-grid">
            {list.map((p) => (
              <button
                key={p.id}
                type="button"
                role="radio"
                aria-checked={chosen === p.id}
                className="preset"
                data-testid={`${testId}-${p.id}`}
                onClick={() => choose(p)}
                title={p.title ?? p.label}
                disabled={p.disabled}
              >
                <Logo icon={p.icon} size={size} />
                <span>{p.label}</span>
                {p.found && <i className="preset-found" aria-label="Available" />}
                {p.added && <Check className="preset-added" size={12} aria-label="Added" />}
              </button>
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}

/** Fields most people never need, folded away unless `open` (then shown inline). */
export function MoreFields({ open, expanded, label = "More", children }: { open?: boolean; expanded?: boolean; label?: string; children: ReactNode }) {
  if (open) return <>{children}</>;
  return (
    <details className="more-fields" open={expanded}>
      <summary>
        <SlidersHorizontal size={14} aria-hidden /> {label}
      </summary>
      {children}
    </details>
  );
}

/** The first free name: `base`, else `base-2`, `base-3`, ... */
export function freeName(base: string, taken: string[]) {
  if (!taken.includes(base)) return base;
  for (let n = 2; ; n++) if (!taken.includes(`${base}-${n}`)) return `${base}-${n}`;
}

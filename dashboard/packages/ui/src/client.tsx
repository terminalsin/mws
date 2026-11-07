"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useActionState, useEffect, useRef, type ReactNode } from "react";
import { useFormStatus } from "react-dom";

import { REGION_COOKIE } from "./zones";

/** A navigation entry. Links inside the current zone navigate on the client;
 * links to another zone are plain anchors, because that page belongs to a
 * different Next.js app and needs a full document load. */
export function NavLink({ href, sameZone, children }: { href: string; sameZone: boolean; children: ReactNode }) {
  const pathname = usePathname() || "/";
  if (!sameZone) {
    return (
      <a className="nav-link" href={href}>
        {children}
      </a>
    );
  }
  const active = href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(href + "/");
  return (
    <Link className={active ? "nav-link active" : "nav-link"} href={href} aria-current={active ? "page" : undefined}>
      {children}
    </Link>
  );
}

const REGIONS = [
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
  "ca-central-1",
  "eu-west-1",
  "eu-west-2",
  "eu-central-1",
  "eu-north-1",
  "ap-south-1",
  "ap-northeast-1",
  "ap-southeast-1",
  "ap-southeast-2",
  "sa-east-1",
];

/** Every zone reads the region from one cookie, so a change here applies to
 * the whole console. */
export function RegionPicker({ region }: { region: string }) {
  const router = useRouter();
  const options = REGIONS.includes(region) ? REGIONS : [region, ...REGIONS];
  return (
    <label className="region">
      <span>Region</span>
      <select
        aria-label="Region"
        value={region}
        onChange={(e) => {
          document.cookie = `${REGION_COOKIE}=${encodeURIComponent(e.target.value)}; path=/; max-age=31536000; samesite=lax`;
          router.refresh();
        }}
      >
        {options.map((r) => (
          <option key={r} value={r}>
            {r}
          </option>
        ))}
      </select>
    </label>
  );
}

export interface ActionResult {
  ok: boolean;
  message: string;
  /** Extra output to show under the form, such as a Lambda response. */
  detail?: string;
}

export type FormAction = (previous: ActionResult | null, form: FormData) => Promise<ActionResult>;

function Submit({ label, tone, confirm }: { label: string; tone?: "danger" | "primary"; confirm?: string }) {
  const { pending } = useFormStatus();
  return (
    <button
      type="submit"
      className={`button ${tone ?? "primary"}`}
      disabled={pending}
      onClick={(e) => {
        if (confirm && !window.confirm(confirm)) e.preventDefault();
      }}
    >
      {pending ? "Working…" : label}
    </button>
  );
}

/** A form bound to a server action. It shows the action's outcome below the
 * fields and, on success, clears them. */
export function ActionForm({
  action,
  submit,
  tone,
  confirm,
  inline,
  children,
  testId,
}: {
  action: FormAction;
  submit: string;
  tone?: "danger" | "primary";
  confirm?: string;
  inline?: boolean;
  children?: ReactNode;
  testId?: string;
}) {
  const [state, run] = useActionState(action, null);
  const form = useRef<HTMLFormElement>(null);
  useEffect(() => {
    if (state?.ok) form.current?.reset();
  }, [state]);
  return (
    <form ref={form} action={run} className={inline ? "action-form inline" : "action-form"} data-testid={testId}>
      {children}
      <div className="form-actions">
        <Submit label={submit} tone={tone} confirm={confirm} />
      </div>
      {state && (
        <div className={state.ok ? "result ok" : "result error"} role="status">
          <span>{state.message}</span>
          {state.detail && <pre>{state.detail}</pre>}
        </div>
      )}
    </form>
  );
}

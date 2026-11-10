"use client";

import {
  ArrowDown,
  ArrowUp,
  Check,
  ChevronDown,
  CloudOff,
  Command,
  Copy,
  CornerDownLeft,
  Globe,
  LayoutGrid,
  List as ListIcon,
  LoaderCircle,
  Plus,
  RotateCw,
  Search,
  SearchX,
  Sparkles,
  X,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import {
  createContext,
  useActionState,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  useTransition,
  type ReactNode,
} from "react";
import { useFormStatus } from "react-dom";

import { iconUrl } from "./catalog";
import { DotMatrix } from "./loaders";
import { machine, useMachine } from "./machine";
import { CheckMark } from "./motion";
import { AUTO, REGION_COOKIE } from "./constants";
import { FormIssuesContext, useFormIssues } from "./fields";
import type { FieldIssue } from "./validation";

/** A service as the navigation needs it (serializable, built on the server). */
export interface NavService {
  id: string;
  short: string;
  icon: string;
  /** Category id, for the "related services" list. */
  category: string;
  /** Landing page. */
  path: string;
  nav: { label: string; path: string; icon: string }[];
}

export interface NavGroup {
  id: string;
  name: string;
  services: NavService[];
}

function Icon({ icon, size = 20 }: { icon: string; size?: number }) {
  return <img className="aws-icon" src={iconUrl(icon)} alt="" width={size} height={size} style={{ width: size, height: size }} />;
}

/** Where a nav path ("/iam?tab=roles") points: its pathname and tab. */
function splitPath(path: string) {
  const [pathname, query = ""] = path.split("?");
  return { pathname, tab: new URLSearchParams(query).get("tab") };
}

/** The service a pathname belongs to: the longest matching path. */
function activeService(services: NavService[], pathname: string) {
  let best: NavService | undefined;
  let length = 0;
  for (const s of services) {
    for (const p of [s.path, ...s.nav.map((n) => splitPath(n.path).pathname)]) {
      if ((pathname === p || pathname.startsWith(p + "/")) && p.length > length) {
        best = s;
        length = p.length;
      }
    }
  }
  return best;
}

function activeItem(service: NavService, pathname: string, tab: string | null) {
  const items = service.nav.map((n) => ({ ...n, ...splitPath(n.path) }));
  const exact = items.find((n) => n.pathname === pathname && n.tab === tab);
  if (exact) return exact.path;
  // A resource page: the section whose name its path mentions ("/iam/roles/x" → Roles).
  const segments = pathname.split("/").filter(Boolean);
  const named = items.find((n) => segments.slice(1).some((seg) => n.label.toLowerCase().startsWith(seg.slice(0, 4).toLowerCase())));
  if (named) return named.path;
  return items.find((n) => pathname.startsWith(n.pathname))?.path;
}

/** The sidebar. Inside a service it is that service's own navigation, as in
 * the AWS console, followed by its neighbours in the same category;
 * elsewhere (home, control plane) it lists every service. */
export function SideNav({ groups }: { groups: NavGroup[] }) {
  const pathname = usePathname() || "/";
  const tab = useSearchParams().get("tab");
  const services = groups.flatMap((g) => g.services);
  const current = activeService(services, pathname);
  if (current) {
    const active = activeItem(current, pathname, tab);
    const related = services.filter((s) => s.category === current.category && s.id !== current.id);
    return (
      <nav aria-label={current.short} className="service-nav">
        <Link className="service-head" href={current.path}>
          <Icon icon={current.icon} size={28} />
          <span>{current.short}</span>
        </Link>
        {current.nav.map((n) => (
          <Link key={n.path} className={n.path === active ? "nav-link active" : "nav-link"} href={n.path} aria-current={n.path === active ? "page" : undefined}>
            <Icon icon={n.icon} size={20} />
            <span>{n.label}</span>
          </Link>
        ))}
        {related.length > 0 && (
          <div className="nav-group related">
            {related.map((s) => (
              <Link key={s.id} className="nav-link" href={s.path}>
                <Icon icon={s.icon} size={20} />
                <span>{s.short}</span>
              </Link>
            ))}
          </div>
        )}
      </nav>
    );
  }
  return (
    <nav aria-label="Services">
      {groups.map((g) => (
        <div key={g.id} className="nav-group">
          <div className="nav-title">{g.name}</div>
          {g.services.map((s) => (
            <Link key={s.id} className="nav-link" href={s.path}>
              <Icon icon={s.icon} />
              <span>{s.short}</span>
            </Link>
          ))}
        </div>
      ))}
    </nav>
  );
}

/** The top bar's Services menu: every service by category, as in AWS. */
export function ServicesMenu({ groups }: { groups: NavGroup[] }) {
  const [open, setOpen] = useState(false);
  const [opened, setOpened] = useState(false);
  const panel = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === "Escape" : !panel.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", close);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", close);
    };
  }, [open]);
  return (
    <div className="services-menu" ref={panel}>
      <button
        type="button"
        className="topbar-button"
        aria-label="Services"
        aria-expanded={open}
        onClick={() => {
          setOpened(true);
          setOpen(!open);
        }}
      >
        <LayoutGrid size={16} aria-hidden />
      </button>
      {/* Kept mounted after the first opening, so closing can animate. */}
      {(open || opened) && (
        <div className="services-panel" role="menu" data-open={open} inert={!open}>
          {groups.map((g) => (
            <div key={g.id} className="services-group">
              <div className="nav-title">{g.name}</div>
              {g.services.map((s) => (
                <Link key={s.id} role="menuitem" className="nav-link" href={s.path} onClick={() => setOpen(false)}>
                  <Icon icon={s.icon} size={24} />
                  <span>{s.short}</span>
                </Link>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/** A sidebar entry, highlighted while its page (or one below it) is open. */
export function NavLink({ href, icon, children }: { href: string; icon?: ReactNode; children: ReactNode }) {
  const pathname = usePathname() || "/";
  const active = href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(href + "/");
  return (
    <Link className={active ? "nav-link active" : "nav-link"} href={href} aria-current={active ? "page" : undefined}>
      {icon}
      <span>{children}</span>
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

/** Every page reads the region from one cookie, so a change here applies to
 * the whole console. */
export function RegionPicker({ region }: { region: string }) {
  const router = useRouter();
  const [switching, start] = useTransition();
  const options = REGIONS.includes(region) ? REGIONS : [region, ...REGIONS];
  return (
    <label className="region" title="Region" data-state={switching ? "switching" : "idle"}>
      {switching ? <LoaderCircle className="spin" size={15} aria-hidden /> : <Globe size={15} aria-hidden />}
      <select
        aria-label="Region"
        value={region}
        aria-busy={switching}
        onChange={(e) => {
          document.cookie = `${REGION_COOKIE}=${encodeURIComponent(e.target.value)}; path=/; max-age=31536000; samesite=lax`;
          start(() => router.refresh());
        }}
      >
        {options.map((r) => (
          <option key={r} value={r}>
            {r}
          </option>
        ))}
      </select>
      <ChevronDown size={13} aria-hidden />
    </label>
  );
}

export interface ActionResult {
  ok: boolean;
  message: string;
  /** Extra output to show under the form, such as a Lambda response. */
  detail?: string;
  /** Problems the server found with specific fields; each shows on its
   * field with repairs (see `Field`), the rest under the form. */
  issues?: FieldIssue[];
}

export type FormAction = (previous: ActionResult | null, form: FormData) => Promise<ActionResult>;

const SheetContext = createContext<(() => void) | null>(null);

/** A submission's life: the button spins while the action runs, confirms
 * with a check when it succeeded, and shakes when it failed. */
type SubmitPhase = "idle" | "pending" | "succeeded" | "failed";
type SubmitEvent = { type: "SUBMIT" } | { type: "RESOLVE"; ok: boolean };
const submission = machine<SubmitPhase, SubmitEvent>({
  initial: "idle",
  states: {
    idle: { on: { SUBMIT: "pending" } },
    pending: { on: { RESOLVE: (e) => (e.ok ? "succeeded" : "failed") } },
    succeeded: { on: { SUBMIT: "pending" }, after: { ms: 1600, to: "idle" } },
    failed: { on: { SUBMIT: "pending" }, after: { ms: 700, to: "idle" } },
  },
});

function Submit({
  label,
  icon,
  tone,
  confirm,
  phase,
}: {
  label: string;
  icon?: ReactNode;
  tone?: "danger" | "primary" | "plain";
  confirm?: string;
  phase: SubmitPhase;
}) {
  const { pending } = useFormStatus();
  const busy = pending || phase === "pending";
  const glyph = busy ? (
    <LoaderCircle className="spin" size={15} aria-hidden />
  ) : phase === "succeeded" ? (
    <CheckMark size={15} />
  ) : (
    icon
  );
  return (
    <button
      type="submit"
      className={icon ? `icon-button ${tone ?? "plain"}` : `button ${tone ?? "primary"}`}
      disabled={busy}
      data-state={busy ? "pending" : phase}
      aria-label={label || undefined}
      title={icon ? label : undefined}
      onClick={(e) => {
        if (confirm && !window.confirm(confirm)) e.preventDefault();
      }}
    >
      {icon ? glyph : null}
      {(!icon || label) && <span className={icon ? "sr-only" : undefined}>{label}</span>}
      {/* The glyph slot is always there, so the button keeps its width as it
          goes from label to spinner to check. */}
      {!icon && <span className="button-glyph">{busy || phase === "succeeded" ? glyph : null}</span>}
    </button>
  );
}

/** A form bound to a server action. A labelled form shows the outcome under
 * its fields; an icon-only form (a row action) reports the outcome as a
 * toast. Inside a sheet, success closes the sheet and confirms with a toast. */
export function ActionForm({
  action,
  submit,
  icon,
  tone,
  confirm,
  inline,
  children,
  testId,
}: {
  action: FormAction;
  /** The button's label (the accessible name for an icon button). */
  submit: string;
  /** Render the submit button as this icon alone. */
  icon?: ReactNode;
  tone?: "danger" | "primary" | "plain";
  confirm?: string;
  inline?: boolean;
  children?: ReactNode;
  testId?: string;
}) {
  const [state, run, isPending] = useActionState(action, null);
  const [, startSubmit] = useTransition();
  const [phase, send] = useMachine(submission);
  const form = useRef<HTMLFormElement>(null);
  const close = useContext(SheetContext);
  const toast = useToast();
  const issues = useFormIssues();
  const { publish, unclaimed } = issues;
  // Every server issue landed on a field: the fields say it, not the form.
  const [inlineOnly, setInlineOnly] = useState(false);
  const quiet = !!icon && !children;
  useEffect(() => {
    if (isPending) send({ type: "SUBMIT" });
  }, [isPending, send]);
  useEffect(() => {
    if (!state) return;
    send({ type: "RESOLVE", ok: state.ok });
    const found = state.ok ? [] : (state.issues ?? []);
    publish(found);
    setInlineOnly(found.length > 0 && unclaimed(found).length === 0);
    if (state.ok) {
      form.current?.reset();
      if (close && !state.detail) {
        // The sheet sinks away; a toast carries the confirmation.
        close();
        toast(state);
        return;
      }
    }
    if (quiet) toast(state);
  }, [state, close, quiet, toast, send, publish, unclaimed]);
  // A submission the fields stopped: focus the first problem and shake its
  // field (each field shows its own message instead of a browser bubble).
  useEffect(() => {
    const el = form.current;
    if (!el) return;
    let first: HTMLElement | null = null;
    const onInvalid = (e: Event) => {
      if (first) return;
      first = e.target as HTMLElement;
      // After the browser has fired every invalid event (and the fields
      // have cancelled theirs).
      setTimeout(() => {
        const target = first;
        first = null;
        if (!target || !e.defaultPrevented) return;
        target.focus();
        const field = target.closest<HTMLElement>(".field");
        if (field) {
          field.removeAttribute("data-shake");
          void field.offsetWidth;
          field.setAttribute("data-shake", "");
        }
      }, 0);
    };
    el.addEventListener("invalid", onInvalid, true);
    return () => el.removeEventListener("invalid", onInvalid, true);
  }, []);
  return (
    <form
      ref={form}
      // Submitted by hand rather than through `action`, which would reset
      // the fields even when the action fails, losing what the person typed
      // and the value the repairs work from.
      onSubmit={(e) => {
        e.preventDefault();
        const data = new FormData(e.currentTarget, (e.nativeEvent as globalThis.SubmitEvent).submitter);
        startSubmit(() => run(data));
      }}
      className={quiet ? "action-icon" : inline ? "action-form inline" : "action-form"}
      data-testid={testId}
      data-state={phase}
      data-tone={tone}
      aria-busy={phase === "pending"}
    >
      <FormIssuesContext.Provider value={issues.value}>{children}</FormIssuesContext.Provider>
      <div className="form-actions">
        <Submit label={submit} icon={icon} tone={tone} confirm={confirm} phase={phase} />
      </div>
      {!quiet && phase === "pending" && (
        <div className="result pending" aria-hidden>
          <DotMatrix pattern="pulse" />
        </div>
      )}
      {state && !quiet && phase !== "pending" && !(inlineOnly && !state.ok) && (
        <div key={state.message + String(state.ok)} className={state.ok ? "result ok" : "result error"} role="status">
          <span>
            {state.ok ? <Check size={15} aria-hidden /> : <X size={15} aria-hidden />}
            {state.message}
          </span>
          {state.detail && <pre>{state.detail}</pre>}
        </div>
      )}
      {state && quiet && (
        <span className="sr-only" role="status">
          {state.message}
        </span>
      )}
    </form>
  );
}

/** A modal sheet opened from an icon button: where creation forms live, so
 * pages show resources rather than empty forms. It rises in on open and
 * sinks out on close (see `.sheet` in styles.css). */
export function Sheet({
  title,
  label,
  icon,
  children,
  testId,
  variant = "icon",
}: {
  title: string;
  /** The trigger's accessible name and tooltip. */
  label: string;
  icon?: ReactNode;
  children: ReactNode;
  testId?: string;
  variant?: "icon" | "button";
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const close = useCallback(() => dialog.current?.close(), []);
  // Each opening starts fresh: forms remount without the last outcome.
  const [opened, setOpened] = useState(0);
  return (
    <>
      <button
        type="button"
        className={variant === "icon" ? "icon-button primary" : "button primary"}
        aria-label={label}
        title={label}
        data-testid={testId ? `${testId}-open` : undefined}
        onClick={() => {
          setOpened((n) => n + 1);
          dialog.current?.showModal();
        }}
      >
        {icon ?? <Plus size={16} aria-hidden />}
        {variant === "button" && <span>{label}</span>}
      </button>
      <dialog
        ref={dialog}
        className="sheet"
        aria-label={title}
        onClick={(e) => {
          if (e.target === dialog.current) close();
        }}
      >
        <div className="sheet-head">
          <h2>{title}</h2>
          <button type="button" className="icon-button plain" aria-label="Close" onClick={close}>
            <X size={16} aria-hidden />
          </button>
        </div>
        <SheetContext.Provider key={opened} value={close}>
          {children}
        </SheetContext.Provider>
      </dialog>
    </>
  );
}

// Toasts: each one enters, waits (paused while hovered), then leaves before
// it is removed, so it never just blinks out.

type Toast = ActionResult & { id: number; phase: "shown" | "leaving" };
const ToastContext = createContext<(r: ActionResult) => void>(() => {});
const useToast = () => useContext(ToastContext);
const LEAVE_MS = 250;

function ToastItem({ toast, dismiss }: { toast: Toast; dismiss: (id: number) => void }) {
  const [paused, setPaused] = useState(false);
  const life = toast.ok ? 3200 : 6000;
  const left = useRef(life);
  useEffect(() => {
    if (paused || toast.phase === "leaving") return;
    const started = Date.now();
    const timer = setTimeout(() => dismiss(toast.id), left.current);
    return () => {
      clearTimeout(timer);
      left.current -= Date.now() - started;
    };
  }, [paused, toast.phase, toast.id, dismiss]);
  return (
    <div
      className={toast.ok ? "toast ok" : "toast error"}
      role={toast.ok ? "status" : "alert"}
      data-state={toast.phase}
      data-paused={paused || undefined}
      style={{ ["--life" as string]: `${life}ms` }}
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
    >
      {toast.ok ? <Check size={15} aria-hidden /> : <X size={15} aria-hidden />}
      <span>{toast.message}</span>
      <button type="button" className="toast-close" aria-label="Dismiss" onClick={() => dismiss(toast.id)}>
        <X size={13} aria-hidden />
      </button>
      <i className="toast-life" aria-hidden />
    </div>
  );
}

export function Toasts({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((r: ActionResult) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t.slice(-3), { ok: r.ok, message: r.message, id, phase: "shown" }]);
  }, []);
  const dismiss = useCallback((id: number) => {
    setToasts((t) => t.map((x) => (x.id === id ? { ...x, phase: "leaving" } : x)));
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), LEAVE_MS);
  }, []);
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toasts" aria-live="polite">
        {toasts.map((t) => (
          <ToastItem key={t.id} toast={t} dismiss={dismiss} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

// Command palette (⌘K): semantic search across every service's resources.

export interface SearchHit {
  id: string;
  service: string;
  serviceName: string;
  icon: string;
  type: string;
  name: string;
  detail?: string;
  href: string;
  score: number;
}

/** The palette's search: typing waits out a short debounce, a request runs,
 * and the answer is results, nothing, or a failure. A newer query supersedes
 * the request in flight. */
type SearchPhase = "closed" | "debouncing" | "loading" | "results" | "empty" | "failed";
type SearchEvent = { type: "OPEN" } | { type: "CLOSE" } | { type: "TYPE" } | { type: "FETCH" } | { type: "LOADED"; count: number } | { type: "FAILED" };
const searching = machine<SearchPhase, SearchEvent>({
  initial: "closed",
  states: {
    closed: { on: { OPEN: "loading", TYPE: "debouncing" } },
    debouncing: { on: { FETCH: "loading", TYPE: "debouncing", CLOSE: "closed" } },
    loading: { on: { LOADED: (e) => (e.count ? "results" : "empty"), FAILED: "failed", TYPE: "debouncing", CLOSE: "closed" } },
    results: { on: { TYPE: "debouncing", OPEN: "loading", CLOSE: "closed" } },
    empty: { on: { TYPE: "debouncing", OPEN: "loading", CLOSE: "closed" } },
    failed: { on: { TYPE: "debouncing", OPEN: "loading", CLOSE: "closed" } },
  },
});

export function CommandPalette() {
  const dialog = useRef<HTMLDialogElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState("");
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [cursor, setCursor] = useState(0);
  const [phase, send] = useMachine(searching);
  // Bumped on every opening, so reopening refreshes what needs attention.
  const [generation, setGeneration] = useState(0);

  const open = useCallback(() => {
    dialog.current?.showModal();
    setGeneration((g) => g + 1);
    send({ type: "OPEN" });
    setTimeout(() => input.current?.select(), 0);
  }, [send]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        open();
      } else if (e.key === "/" && !(e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement || e.target instanceof HTMLSelectElement || (e.target as HTMLElement)?.isContentEditable)) {
        e.preventDefault();
        open();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  useEffect(() => {
    if (generation === 0) return;
    const controller = new AbortController();
    const timer = setTimeout(
      async () => {
        send({ type: "FETCH" });
        try {
          const response = await fetch(`/api/search?q=${encodeURIComponent(query)}`, { signal: controller.signal });
          if (!response.ok) throw new Error(String(response.status));
          const body = (await response.json()) as { hits: SearchHit[] };
          setHits(body.hits);
          setCursor(0);
          send({ type: "LOADED", count: body.hits.length });
        } catch {
          if (!controller.signal.aborted) send({ type: "FAILED" });
        }
      },
      query ? 140 : 0,
    );
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [query, generation, send]);

  const grouped = useMemo(() => {
    const groups = new Map<string, SearchHit[]>();
    for (const h of hits) groups.set(h.serviceName, [...(groups.get(h.serviceName) ?? []), h]);
    return [...groups.entries()];
  }, [hits]);

  const go = (hit: SearchHit | undefined) => {
    if (hit) window.location.assign(hit.href);
  };
  const busy = phase === "loading" || phase === "debouncing";
  const stale = busy && hits.length > 0;

  return (
    <>
      <button type="button" className="search-trigger" onClick={open} aria-label="Search">
        <Search size={15} aria-hidden />
        <span>Search</span>
        <kbd>
          <Command size={11} aria-hidden />K
        </kbd>
      </button>
      <dialog
        ref={dialog}
        className="palette"
        aria-label="Search resources"
        data-state={phase}
        onClose={() => send({ type: "CLOSE" })}
        onClick={(e) => {
          if (e.target === dialog.current) dialog.current?.close();
        }}
      >
        <div className="palette-input">
          <span className="icon-swap" data-state={phase === "loading" ? "busy" : "idle"}>
            <Search size={18} aria-hidden />
            <DotMatrix pattern="scan" size={3} />
          </span>
          <input
            ref={input}
            value={query}
            placeholder="Search resources"
            aria-label="Search resources"
            onChange={(e) => {
              setQuery(e.target.value);
              send({ type: "TYPE" });
            }}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setCursor((c) => Math.min(c + 1, hits.length - 1));
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                setCursor((c) => Math.max(c - 1, 0));
              } else if (e.key === "Enter") {
                go(hits[cursor]);
              }
            }}
          />
          {query && (
            <button
              type="button"
              className="palette-clear"
              aria-label="Clear"
              onClick={() => {
                setQuery("");
                send({ type: "TYPE" });
                input.current?.focus();
              }}
            >
              <X size={14} aria-hidden />
            </button>
          )}
        </div>
        <div className="palette-results" role="listbox" aria-label="Results" aria-busy={busy} data-stale={stale || undefined}>
          {busy && hits.length === 0 && (
            <div className="palette-skeleton" aria-hidden>
              {[64, 48, 72, 40].map((w, i) => (
                <div key={i} className="palette-hit">
                  <span className="skeleton-block" style={{ width: 22, height: 22 }} />
                  <span className="skeleton-line" style={{ width: `${w}%` }} />
                </div>
              ))}
            </div>
          )}
          {!query && hits.length > 0 && <div className="palette-caption">Needs attention</div>}
          {grouped.map(([serviceName, list]) => (
            <div key={serviceName} className="palette-group">
              <div className="palette-group-title">{serviceName}</div>
              {list.map((h) => {
                const index = hits.indexOf(h);
                return (
                  <a
                    key={h.id}
                    href={h.href}
                    role="option"
                    aria-selected={index === cursor}
                    className={index === cursor ? "palette-hit active" : "palette-hit"}
                    onMouseEnter={() => setCursor(index)}
                  >
                    <Icon icon={h.icon} size={22} />
                    <span className="palette-hit-name">{h.name}</span>
                    {h.detail && <span className="palette-hit-type">{h.detail}</span>}
                    {index === cursor && <CornerDownLeft size={14} aria-hidden />}
                  </a>
                );
              })}
            </div>
          ))}
          {phase === "empty" && query && (
            <div className="palette-empty">
              <SearchX size={28} aria-hidden />
              No matches
            </div>
          )}
          {phase === "failed" && (
            <div className="palette-empty">
              <CloudOff size={28} aria-hidden />
              Search is unavailable
            </div>
          )}
        </div>
        <div className="palette-foot" aria-hidden>
          <span>
            <kbd>
              <ArrowUp size={11} />
            </kbd>
            <kbd>
              <ArrowDown size={11} />
            </kbd>
          </span>
          <span>
            <kbd>
              <CornerDownLeft size={11} />
            </kbd>
          </span>
          <span>
            <kbd>esc</kbd>
          </span>
          {hits.length > 0 && <span className="palette-count">{hits.length}</span>}
        </div>
      </dialog>
    </>
  );
}

/** Copies `value` and confirms with a check. */
export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 1400);
    return () => clearTimeout(timer);
  }, [copied]);
  return (
    <button
      type="button"
      className="copy-button"
      aria-label={copied ? "Copied" : label}
      title={copied ? "Copied" : label}
      data-state={copied ? "copied" : "idle"}
      onClick={async (e) => {
        e.preventDefault();
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
        } catch {
          // clipboard blocked (insecure origin): leave the button as is
        }
      }}
    >
      {copied ? <CheckMark size={13} /> : <Copy size={13} aria-hidden />}
    </button>
  );
}

/** The navigation progress bar: starts when a link is followed, completes
 * when the new page is there, and fades away. Fast navigations never show
 * it (the bar appears after a short delay, see styles.css). */
type RoutePhase = "idle" | "loading" | "finishing";
type RouteEvent = { type: "START" } | { type: "DONE" };
const routing = machine<RoutePhase, RouteEvent>({
  initial: "idle",
  states: {
    idle: { on: { START: "loading" } },
    loading: { on: { DONE: "finishing", START: "loading" }, after: { ms: 20000, to: "finishing" } },
    finishing: { on: { START: "loading" }, after: { ms: 450, to: "idle" } },
  },
});

export function RouteProgress() {
  const pathname = usePathname();
  const search = useSearchParams().toString();
  const [phase, send] = useMachine(routing);
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    send({ type: "DONE" });
  }, [pathname, search, send]);
  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      const a = (e.target as Element | null)?.closest?.("a[href]") as HTMLAnchorElement | null;
      if (!a || (a.target && a.target !== "_self") || a.hasAttribute("download")) return;
      const url = new URL(a.href, window.location.href);
      if (url.origin !== window.location.origin || url.pathname.startsWith("/api/") || url.pathname.includes("/api/")) return;
      if (url.pathname === window.location.pathname && url.search === window.location.search) return;
      send({ type: "START" });
    };
    // Back from the page cache: nothing is loading any more.
    const onShow = () => send({ type: "DONE" });
    document.addEventListener("click", onClick, true);
    window.addEventListener("pageshow", onShow);
    return () => {
      document.removeEventListener("click", onClick, true);
      window.removeEventListener("pageshow", onShow);
    };
  }, [send]);
  return <div className="route-progress" data-state={phase} aria-hidden />;
}

/** Keeps a page current while something on it is changing: while any
 * `LiveRefresh` is mounted (and `when` holds), the page re-renders on the
 * server every few seconds, backing off from `every` ms to 15 s and stopping
 * after ten minutes. One timer serves every instance on the page; it waits
 * while the tab is hidden or the person is typing, so forms are not
 * disturbed. `Status` mounts one for transitional words ("Creating",
 * "CREATE_IN_PROGRESS"); pages add their own for states it can't tell. */
export function LiveRefresh({ when = true, every = 2500 }: { when?: boolean; every?: number }) {
  const router = useRouter();
  useEffect(() => {
    if (!when) return;
    const entry = { every, refresh: () => router.refresh() };
    live.watchers.add(entry);
    schedule();
    return () => {
      live.watchers.delete(entry);
      if (!live.watchers.size && live.timer) {
        clearTimeout(live.timer);
        live.timer = undefined;
      }
    };
  }, [when, every, router]);
  return null;
}

const live: {
  watchers: Set<{ every: number; refresh: () => void }>;
  timer?: ReturnType<typeof setTimeout>;
  delay: number;
  since: number;
} = { watchers: new Set(), delay: 0, since: 0 };

function schedule() {
  if (live.timer || !live.watchers.size) return;
  const first = Math.min(...[...live.watchers].map((w) => w.every));
  if (!live.delay || Date.now() - live.since > 600_000 + live.delay) {
    live.delay = first;
    live.since = Date.now();
  }
  live.timer = setTimeout(() => {
    live.timer = undefined;
    if (!live.watchers.size || Date.now() - live.since > 600_000) return;
    const typing = document.activeElement?.matches?.("input, textarea, select, [contenteditable]");
    if (!document.hidden && !typing) {
      const [w] = live.watchers;
      w?.refresh();
    }
    live.delay = Math.min(15_000, Math.round(live.delay * 1.4));
    schedule();
  }, live.delay);
}

/** What a service shows when a page throws: the failure, and a retry that
 * re-renders the page on the server. */
export function ErrorView({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  const router = useRouter();
  const [retrying, start] = useTransition();
  return (
    <div className="error-view" role="alert">
      <CloudOff size={40} aria-hidden />
      <h2>Something went wrong</h2>
      <p className="muted">{error.message || "The page failed to render."}</p>
      {error.digest && <code className="muted">{error.digest}</code>}
      <button
        type="button"
        className="button primary"
        disabled={retrying}
        onClick={() =>
          start(() => {
            router.refresh();
            reset();
          })
        }
      >
        Try again
        {retrying ? <LoaderCircle className="spin" size={15} aria-hidden /> : <RotateCw size={15} aria-hidden />}
      </button>
    </div>
  );
}

/** A prerequisite picker: an existing resource, or one the form creates on
 * submit (`creates` names it). Starts on "create" when nothing exists yet. */
export function AutoPick({
  name,
  label,
  options,
  creates,
  preferred,
  testId,
}: {
  name: string;
  label: string;
  options: { value: string; label: string }[];
  /** What the automatic option makes, e.g. the role name. */
  creates: string;
  /** Start on this existing option (e.g. the one made automatically last time). */
  preferred?: string;
  testId?: string;
}) {
  const [auto, setAuto] = useState(options.length === 0);
  const initial = options.find((o) => o.value === preferred || o.label === creates)?.value ?? options[0]?.value;
  return (
    <div className="field auto-pick" data-testid={testId}>
      <span className="field-label">{label}</span>
      <div className="auto-pick-row">
        {auto ? (
          <span className="auto-new" data-testid={testId ? `${testId}-auto` : undefined}>
            <Sparkles size={14} aria-hidden />
            <span className="clip">{creates}</span>
            <input type="hidden" name={name} value={AUTO} />
          </span>
        ) : (
          <select name={name} aria-label={label} defaultValue={initial}>
            {options.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        )}
        <span className="auto-toggle" role="group" aria-label={label}>
          <button type="button" aria-pressed={auto} title="Create automatically" aria-label="Create automatically" onClick={() => setAuto(true)}>
            <Sparkles size={15} aria-hidden />
          </button>
          <button type="button" aria-pressed={!auto} title="Choose existing" aria-label="Choose existing" disabled={options.length === 0} onClick={() => setAuto(false)}>
            <ListIcon size={15} aria-hidden />
          </button>
        </span>
      </div>
    </div>
  );
}

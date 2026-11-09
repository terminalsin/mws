"use client";

import { Check, ChevronDown, Command, CornerDownLeft, Globe, LayoutGrid, List as ListIcon, LoaderCircle, Plus, Search, Sparkles, X } from "lucide-react";
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
  type ReactNode,
} from "react";
import { useFormStatus } from "react-dom";

import { iconUrl } from "./catalog";
import { AUTO, REGION_COOKIE, type ZoneId } from "./zones";

/** A service as the navigation needs it (serializable, built on the server). */
export interface NavService {
  id: string;
  short: string;
  icon: string;
  zone: ZoneId;
  /** Landing path inside its zone. */
  path: string;
  /** Absolute URL of the landing page (for other zones). */
  href: string;
  nav: { label: string; path: string; icon: string; href: string }[];
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

/** The service a pathname belongs to in this zone: the longest matching path. */
function activeService(services: NavService[], zone: ZoneId, pathname: string) {
  let best: NavService | undefined;
  let length = 0;
  for (const s of services) {
    if (s.zone !== zone) continue;
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
 * the AWS console; elsewhere (home, control plane) it lists every service. */
export function SideNav({ zone, groups }: { zone: ZoneId; groups: NavGroup[] }) {
  const pathname = usePathname() || "/";
  const tab = useSearchParams().get("tab");
  const services = groups.flatMap((g) => g.services);
  const current = zone === "shell" ? undefined : activeService(services, zone, pathname);
  if (current) {
    const active = activeItem(current, pathname, tab);
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
        {services.some((s) => s.zone === zone && s.id !== current.id) && (
          <div className="nav-group related">
            {services
              .filter((s) => s.zone === zone && s.id !== current.id)
              .map((s) => (
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
          {g.services.map((s) =>
            s.zone === zone ? (
              <Link key={s.id} className="nav-link" href={s.path}>
                <Icon icon={s.icon} />
                <span>{s.short}</span>
              </Link>
            ) : (
              <a key={s.id} className="nav-link" href={s.href}>
                <Icon icon={s.icon} />
                <span>{s.short}</span>
              </a>
            ),
          )}
        </div>
      ))}
    </nav>
  );
}

/** The top bar's Services menu: every service by category, as in AWS. */
export function ServicesMenu({ groups }: { groups: NavGroup[] }) {
  const [open, setOpen] = useState(false);
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
      <button type="button" className="topbar-button" aria-label="Services" aria-expanded={open} onClick={() => setOpen(!open)}>
        <LayoutGrid size={16} aria-hidden />
      </button>
      {open && (
        <div className="services-panel" role="menu">
          {groups.map((g) => (
            <div key={g.id} className="services-group">
              <div className="nav-title">{g.name}</div>
              {g.services.map((s) => (
                <a key={s.id} role="menuitem" className="nav-link" href={s.href}>
                  <Icon icon={s.icon} size={24} />
                  <span>{s.short}</span>
                </a>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/** A sidebar entry. Links inside the current zone navigate on the client;
 * links to another zone are plain anchors, because that page belongs to a
 * different Next.js app and needs a full document load. */
export function NavLink({
  href,
  zonePath,
  sameZone,
  icon,
  children,
}: {
  href: string;
  /** The path inside the current zone, when the link belongs to it. */
  zonePath?: string;
  sameZone: boolean;
  icon?: ReactNode;
  children: ReactNode;
}) {
  const pathname = usePathname() || "/";
  const target = zonePath ?? href;
  const active = sameZone && (target === "/" ? pathname === "/" : pathname === target || pathname.startsWith(target + "/"));
  const body = (
    <>
      {icon}
      <span>{children}</span>
    </>
  );
  if (!sameZone) {
    return (
      <a className="nav-link" href={href}>
        {body}
      </a>
    );
  }
  return (
    <Link className={active ? "nav-link active" : "nav-link"} href={target} aria-current={active ? "page" : undefined}>
      {body}
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
    <label className="region" title="Region">
      <Globe size={15} aria-hidden />
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
      <ChevronDown size={13} aria-hidden />
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

const SheetContext = createContext<(() => void) | null>(null);

function Submit({
  label,
  icon,
  tone,
  confirm,
}: {
  label: string;
  icon?: ReactNode;
  tone?: "danger" | "primary" | "plain";
  confirm?: string;
}) {
  const { pending } = useFormStatus();
  return (
    <button
      type="submit"
      className={icon ? `icon-button ${tone ?? "plain"}` : `button ${tone ?? "primary"}`}
      disabled={pending}
      aria-label={label || undefined}
      title={icon ? label : undefined}
      onClick={(e) => {
        if (confirm && !window.confirm(confirm)) e.preventDefault();
      }}
    >
      {pending ? <LoaderCircle className="spin" size={15} aria-hidden /> : icon}
      {(!icon || label) && <span className={icon ? "sr-only" : undefined}>{label}</span>}
    </button>
  );
}

/** A form bound to a server action. A labelled form shows the outcome under
 * its fields; an icon-only form (a row action) reports failures as a toast.
 * Inside a sheet, success closes the sheet. */
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
  const [state, run] = useActionState(action, null);
  const form = useRef<HTMLFormElement>(null);
  const close = useContext(SheetContext);
  const toast = useToast();
  const quiet = !!icon && !children;
  useEffect(() => {
    if (!state) return;
    if (state.ok) {
      form.current?.reset();
      if (close && !state.detail) close();
    }
    if (quiet) toast(state);
  }, [state, close, quiet, toast]);
  return (
    <form
      ref={form}
      action={run}
      className={quiet ? "action-icon" : inline ? "action-form inline" : "action-form"}
      data-testid={testId}
    >
      {children}
      <div className="form-actions">
        <Submit label={submit} icon={icon} tone={tone} confirm={confirm} />
      </div>
      {state && !quiet && (
        <div className={state.ok ? "result ok" : "result error"} role="status">
          <span>{state.message}</span>
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
 * pages show resources rather than empty forms. */
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

// Toasts

type Toast = ActionResult & { id: number };
const ToastContext = createContext<(r: ActionResult) => void>(() => {});
const useToast = () => useContext(ToastContext);

export function Toasts({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((r: ActionResult) => {
    if (r.ok) return;
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { ...r, id }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 6000);
  }, []);
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toasts" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={t.ok ? "toast ok" : "toast error"} role="alert">
            {t.ok ? <Check size={15} aria-hidden /> : <X size={15} aria-hidden />}
            <span>{t.message}</span>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

// Command palette (⌘K): semantic search across every zone's resources.

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

export function CommandPalette() {
  const dialog = useRef<HTMLDialogElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState("");
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [loading, setLoading] = useState(false);
  const [cursor, setCursor] = useState(0);

  const open = useCallback(() => {
    dialog.current?.showModal();
    setTimeout(() => input.current?.select(), 0);
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        open();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  useEffect(() => {
    if (!dialog.current?.open && query === "") return;
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      setLoading(true);
      try {
        const response = await fetch(`/api/search?q=${encodeURIComponent(query)}`, { signal: controller.signal });
        const body = (await response.json()) as { hits: SearchHit[] };
        setHits(body.hits);
        setCursor(0);
      } catch {
        // aborted or offline
      } finally {
        setLoading(false);
      }
    }, 120);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [query]);

  const grouped = useMemo(() => {
    const groups = new Map<string, SearchHit[]>();
    for (const h of hits) groups.set(h.serviceName, [...(groups.get(h.serviceName) ?? []), h]);
    return [...groups.entries()];
  }, [hits]);

  const go = (hit: SearchHit | undefined) => {
    if (hit) window.location.assign(hit.href);
  };

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
        onClick={(e) => {
          if (e.target === dialog.current) dialog.current?.close();
        }}
      >
        <div className="palette-input">
          {loading ? <LoaderCircle className="spin" size={18} aria-hidden /> : <Search size={18} aria-hidden />}
          <input
            ref={input}
            value={query}
            placeholder="Search resources"
            aria-label="Search resources"
            onChange={(e) => setQuery(e.target.value)}
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
        </div>
        <div className="palette-results" role="listbox" aria-label="Results">
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
          {!loading && query && hits.length === 0 && <div className="palette-empty">No matches</div>}
        </div>
      </dialog>
    </>
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

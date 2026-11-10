import {
  ChevronLeft,
  ChevronRight,
  File,
  FileArchive,
  FileCode,
  FileImage,
  FileJson,
  FileSpreadsheet,
  FileText,
  FileVideo,
  Folder,
  SlidersHorizontal,
} from "lucide-react";
import Link from "next/link";
import { Suspense, type ReactNode } from "react";

import { navigation, iconUrl } from "./catalog";
import { CommandPalette, CopyButton, LiveRefresh, NavLink, RegionPicker, RouteProgress, ServicesMenu, SideNav, Toasts, type NavGroup } from "./client";
import { CountUp } from "./motion";
import { FieldShell, type FieldRules } from "./fields";

export { AUTO } from "./constants";
export type { FieldRules } from "./fields";
export type { FieldIssue, Format, Generate, Issue, Repair, Rule, Rules } from "./validation";
export { Asciify, CheckMark, CountUp, Segments } from "./motion";
export { DotMatrix, type DotPattern } from "./loaders";
export {
  ActionForm,
  AutoPick,
  CommandPalette,
  CopyButton,
  ErrorView,
  NavLink,
  RegionPicker,
  RouteProgress,
  Sheet,
  Toasts,
  type ActionResult,
  type FormAction,
  type SearchHit,
} from "./client";
export { CATEGORIES, SERVICES, iconUrl, navigation, runtimeIcon, service, type Category, type CategoryId, type NavItem, type Service } from "./catalog";
export { REGION_COOKIE } from "./constants";

export interface FrameInfo {
  endpoint: string;
  region: string;
  /** The caller's account, or null when MWS could not be reached. */
  account: string | null;
  principal: string | null;
  error: string | null;
}

/** An icon from the official AWS set ("service/AWSLambda", "resource/..."). */
export function AwsIcon({ icon, size = 20, label }: { icon: string; size?: number; label?: string }) {
  return (
    <img
      className="aws-icon"
      src={iconUrl(icon)}
      alt={label ?? ""}
      width={size}
      height={size}
      style={{ width: size, height: size }}
      loading="lazy"
    />
  );
}

/** The page chrome around every page: the sidebar and a toolbar with
 * search, region and account. */
export function Frame({ info, children }: { info: FrameInfo; children: ReactNode }) {
  const groups: NavGroup[] = navigation().map(({ category, services }) => ({
    id: category.id,
    name: category.name,
    services: services.map((s) => ({
      id: s.id,
      short: s.short,
      icon: s.icon,
      category: s.category,
      path: s.path!,
      nav: s.nav ?? [],
    })),
  }));
  const home = (
    <Link className="brand" href="/" aria-label="MWS home">
      {brand}
    </Link>
  );
  return (
    <Toasts>
      <div className="frame">
        <header className="topbar">
          <Suspense>
            <RouteProgress />
          </Suspense>
          <ServicesMenu groups={groups} />
          {home}
          <CommandPalette />
          <div className="topbar-end">
            <span
              className={info.error ? "health down" : "health up"}
              role="img"
              aria-label={info.error ? "MWS unreachable" : "MWS connected"}
              title={info.error ? `MWS unreachable at ${info.endpoint}` : `MWS at ${info.endpoint}`}
            />
            {info.account && (
              <span className="account" title={info.principal ?? undefined}>
                {info.account}
              </span>
            )}
            <RegionPicker region={info.region} />
          </div>
        </header>
        <div className="frame-body">
          <aside className="sidebar">
            <Suspense>
              <SideNav groups={groups} />
            </Suspense>
            <div className="nav-foot">
              <NavLink href="/control" icon={<SlidersHorizontal size={17} aria-hidden />}>
                Control plane
              </NavLink>
            </div>
          </aside>
          <div className="main">
            {info.error && (
              <div className="banner error" role="alert">
                MWS is not reachable at <code>{info.endpoint}</code>. Start it with <code>cargo run -p mws</code>.
              </div>
            )}
            <main className="content">{children}</main>
          </div>
        </div>
      </div>
    </Toasts>
  );
}

const brand = (
  <>
    <span className="brand-mark">MWS</span>
    <span className="brand-name">Console</span>
  </>
);

/** A page's title row: the service or resource icon, the title, and its
 * actions as icon buttons. */
export function Page({
  title,
  icon,
  back,
  subtitle,
  actions,
  children,
}: {
  title: ReactNode;
  icon?: string;
  back?: { href: string; label: string };
  /** One line that identifies the resource (an ARN, a URL), never a description. */
  subtitle?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <>
      <div className="page-head">
        {back && (
          <Link className="back" href={back.href}>
            <ChevronLeft size={15} aria-hidden />
            {back.label}
          </Link>
        )}
        <div className="page-title">
          {icon && <AwsIcon icon={icon} size={34} />}
          <div className="page-title-text">
            <h1>{title}</h1>
            {subtitle && (
              <div className="subtitle">
                <span>{subtitle}</span>
                {typeof subtitle === "string" && <CopyButton value={subtitle} label="Copy identifier" />}
              </div>
            )}
          </div>
          {actions && <div className="page-actions">{actions}</div>}
        </div>
      </div>
      {children}
    </>
  );
}

/** A titled block of content. */
export function Section({
  title,
  count,
  icon,
  actions,
  children,
  plain,
}: {
  title?: ReactNode;
  count?: number;
  icon?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  /** No card around the children (for lists, which draw their own). */
  plain?: boolean;
}) {
  return (
    <section className={plain ? "section plain" : "section"}>
      {(title || actions) && (
        <div className="section-head">
          <h2>
            {icon}
            {title}
            {count !== undefined && <span className="count">{count}</span>}
          </h2>
          {actions && <div className="section-actions">{actions}</div>}
        </div>
      )}
      <div className="section-body">{children}</div>
    </section>
  );
}

export interface Row {
  key: string;
  icon?: ReactNode;
  title: ReactNode;
  subtitle?: ReactNode;
  href?: string;
  /** Rendered on the right: pills, numbers. */
  meta?: ReactNode;
  /** Row actions: icon buttons. */
  actions?: ReactNode;
  /** Load the target as a new document (downloads, pages outside the console). */
  external?: boolean;
}

/** An inset grouped list, the console's main way to show resources. */
export function List({ rows, label, empty }: { rows: Row[]; label?: string; empty?: ReactNode }) {
  if (rows.length === 0) return empty ? <>{empty}</> : null;
  return (
    <ul className="list" aria-label={label}>
      {rows.map((r) => {
        const body = (
          <>
            {r.icon && <span className="row-icon">{r.icon}</span>}
            <span className="row-text">
              <span className="row-title">{r.title}</span>
              {r.subtitle && <span className="row-subtitle">{r.subtitle}</span>}
            </span>
            {r.meta && <span className="row-meta">{r.meta}</span>}
            {r.href && <ChevronRight className="row-chevron" size={16} aria-hidden />}
          </>
        );
        return (
          <li key={r.key} className="row">
            {r.href ? (
              r.external ? (
                <a className="row-main" href={r.href}>
                  {body}
                </a>
              ) : (
                <Link className="row-main" href={r.href}>
                  {body}
                </Link>
              )
            ) : (
              <div className="row-main">{body}</div>
            )}
            {r.actions && <span className="row-actions">{r.actions}</span>}
          </li>
        );
      })}
    </ul>
  );
}

export interface Column<T> {
  header: ReactNode;
  cell: (row: T) => ReactNode;
  className?: string;
}

/** A dense table, for data that is naturally tabular (log events, datapoints). */
export function Table<T>({
  columns,
  rows,
  empty,
  rowKey,
  label,
}: {
  columns: Column<T>[];
  rows: T[];
  empty?: ReactNode;
  rowKey: (row: T) => string;
  label?: string;
}) {
  if (rows.length === 0) return empty ? <>{empty}</> : null;
  return (
    <div className="table-wrap">
      <table aria-label={label}>
        <thead>
          <tr>
            {columns.map((c, i) => (
              <th key={i} className={c.className}>
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={rowKey(row)}>
              {columns.map((c, i) => (
                <td key={i} className={c.className}>
                  {c.cell(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** What a page shows when it has nothing: the service icon and, at most, the
 * one action that changes that. */
export function Empty({ icon, children, action }: { icon?: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      {icon && <AwsIcon icon={icon} size={44} />}
      {children && <div>{children}</div>}
      {action}
    </div>
  );
}

export type Tone = "neutral" | "good" | "warn" | "bad" | "info";

export function Pill({ tone = "neutral", icon, children, title }: { tone?: Tone; icon?: ReactNode; children?: ReactNode; title?: string }) {
  return (
    <span className={`pill ${tone}`} title={title}>
      {icon}
      {children}
    </span>
  );
}

/** States that are on their way somewhere ("creating", "pending",
 * "UPDATE_IN_PROGRESS"): their dot pulses. Steady -ing words are not. */
const TRANSITIONAL = /(ing|pending|progress|_in_progress)$/i;
const STEADY = /^(running|missing|warning|existing|pending acceptance)$/i;

export function transitional(word: string) {
  const w = word.trim();
  return TRANSITIONAL.test(w) && !STEADY.test(w);
}

/** The footer of a list that stopped before the end: how many are shown,
 * and a link to the next page (built by the page, e.g. `?token=...`). Never
 * cut a list without one. */
export function More({ shown, href, noun = "items" }: { shown: number; href?: string; noun?: string }) {
  if (!href) return null;
  return (
    <p className="more-items">
      <span>
        First {shown.toLocaleString()} {noun}
      </span>
      <Link href={href} data-testid="load-more">
        Next page
      </Link>
    </p>
  );
}

/** A status as a colored dot with its word. */
export function Status({ tone, children }: { tone: Tone; children: ReactNode }) {
  const live = typeof children === "string" && transitional(children);
  return (
    <span className={`status ${tone}`} data-live={live || undefined}>
      <span className="dot" aria-hidden />
      {children}
      {live ? <LiveRefresh /> : null}
    </span>
  );
}

type Spec = { icon: ReactNode; value: ReactNode; label: string };

/** A resource's vital signs as icon + value chips, the label kept for
 * tooltips and screen readers: what Facts says in words, said visually. */
export function Specs({ items }: { items: (Spec | null | false | undefined | "" | 0)[] }) {
  return (
    <ul className="specs">
      {items
        .filter((x): x is Spec => !!x)
        .map((x) => (
          <li key={x.label} title={x.label}>
            <span className="spec-icon" aria-hidden>
              {x.icon}
            </span>
            <span className="sr-only">{x.label}</span>
            <span>{x.value}</span>
          </li>
        ))}
    </ul>
  );
}

export function Facts({ items }: { items: ([ReactNode, ReactNode] | null | false | undefined | "" | 0)[] }) {
  return (
    <dl className="facts">
      {items
        .filter((x): x is [ReactNode, ReactNode] => !!x)
        .map(([k, v], i) => (
          <div key={i}>
            <dt>{k}</dt>
            <dd>{v ?? <span className="muted">—</span>}</dd>
          </div>
        ))}
    </dl>
  );
}

/** Shows text as-is, or indented when it is JSON. */
export function CodeBlock({ value, label }: { value: string | undefined | null; label?: string }) {
  if (value == null || value === "") return <span className="muted">—</span>;
  let text = value;
  try {
    text = JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    // not JSON: show as-is
  }
  return (
    <pre className="code" aria-label={label}>
      {text}
    </pre>
  );
}

export function ErrorNotice({ error }: { error: string }) {
  return (
    <div className="banner error" role="alert">
      {error}
    </div>
  );
}

/** A big number with a small label. */
export function Metric({ label, value, tone, icon, href }: { label: string; value: ReactNode; tone?: Tone; icon?: ReactNode; href?: string }) {
  const body = (
    <>
      <div className="metric-label">
        {icon}
        {label}
      </div>
      <div className={`metric-value ${tone ?? ""}`}>{typeof value === "number" ? <CountUp value={value} /> : value}</div>
    </>
  );
  return href ? (
    <a className="metric link" href={href}>
      {body}
    </a>
  ) : (
    <div className="metric">{body}</div>
  );
}

export function Metrics({ children }: { children: ReactNode }) {
  return <div className="metrics">{children}</div>;
}

/** A labelled form control. It validates in place: the control's
 * attributes plus `rule` (from `@mws-dashboard/ui/model/<model>`) and the
 * shortcut props decide what is valid, problems replace the hint, and
 * repairs are offered as one-click chips. */
export function Field({ label, hint, children, ...rules }: { label: string; hint?: ReactNode; children: ReactNode } & FieldRules) {
  return (
    <FieldShell label={label} hint={hint} {...rules}>
      {children}
    </FieldShell>
  );
}

export function Tags({ tags }: { tags: { Key?: string; Value?: string }[] | Record<string, string> | undefined }) {
  const list = Array.isArray(tags) ? tags.map((t) => [t.Key ?? "", t.Value ?? ""]) : Object.entries(tags ?? {});
  if (list.length === 0) return null;
  return (
    <span className="chips">
      {list.map(([k, v]) => (
        <span key={k} className="tag">
          <span>{k}</span>
          {v && <b>{v}</b>}
        </span>
      ))}
    </span>
  );
}

/** Sections a page's resources were sorted into (by `@mws-dashboard/ai`),
 * shown as one list when sectioning would not help: few items, or all in one
 * section. */
export function Curated<T>({
  sections,
  row,
  label,
  empty,
}: {
  sections: { id: string; title: string; items: T[] }[];
  row: (item: T) => Row;
  label?: string;
  empty?: ReactNode;
}) {
  const filled = sections.filter((s) => s.items.length > 0);
  const all = filled.flatMap((s) => s.items);
  if (all.length === 0) return empty ? <>{empty}</> : null;
  if (filled.length <= 1 || all.length < 6) return <List label={label} rows={all.map(row)} />;
  return (
    <>
      {filled.map((s) => (
        <Section key={s.id} title={s.title} count={s.items.length} plain>
          <List label={`${label ?? ""} ${s.title}`.trim()} rows={s.items.map(row)} />
        </Section>
      ))}
    </>
  );
}

/** A file-type glyph for an object key. */
export function FileIcon({ name, folder, size = 18 }: { name: string; folder?: boolean; size?: number }) {
  if (folder) return <Folder size={size} aria-hidden fill="currentColor" fillOpacity={0.15} />;
  const ext = name.split(".").pop()?.toLowerCase() ?? "";
  const Icon =
    ext === "json"
      ? FileJson
      : ["png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "avif"].includes(ext)
        ? FileImage
        : ["mp4", "mov", "webm", "mkv"].includes(ext)
          ? FileVideo
          : ["zip", "gz", "tgz", "tar", "bz2", "7z", "jar"].includes(ext)
            ? FileArchive
            : ["csv", "tsv", "parquet", "xlsx", "orc", "avro"].includes(ext)
              ? FileSpreadsheet
              : ["js", "ts", "py", "rs", "go", "java", "html", "css", "sh", "yaml", "yml", "xml", "toml"].includes(ext)
                ? FileCode
                : ["txt", "md", "log", "pdf"].includes(ext)
                  ? FileText
                  : File;
  return <Icon size={size} aria-hidden />;
}

/** A shimmering stand-in for content that is on its way. */
export function Skeleton({ width, height, block }: { width?: number | string; height?: number | string; block?: boolean }) {
  return <span className={block ? "skeleton-block" : "skeleton-line"} style={{ width, height }} aria-hidden />;
}

/** What a page looks like while it loads: its title row, then either a list
 * (index pages), vital signs and facts (resource pages), or tiles (home).
 * Every page's `loading.tsx` renders one. */
export function PageSkeleton({ variant = "list" }: { variant?: "list" | "detail" | "home" }) {
  const rows = [62, 48, 70, 40, 56, 66, 44];
  return (
    <div className="page-skeleton" aria-busy="true" aria-live="polite" data-testid="page-skeleton">
      <span className="sr-only">Loading</span>
      <div className="page-head">
        <div className="page-title">
          <Skeleton block width={34} height={34} />
          <div className="page-title-text">
            <Skeleton width={variant === "detail" ? 280 : 180} height={28} />
            {variant === "detail" && (
              <div className="subtitle">
                <Skeleton width={360} height={12} />
              </div>
            )}
          </div>
        </div>
      </div>
      {variant === "detail" && (
        <>
          <div className="skeleton-specs">
            {[110, 90, 130, 100].map((w, i) => (
              <span key={i} className="skeleton-spec">
                <Skeleton block width={16} height={16} />
                <Skeleton width={w} />
              </span>
            ))}
          </div>
          <div className="segments">
            {[72, 96, 64].map((w, i) => (
              <span key={i} className="segment">
                <Skeleton width={w} />
              </span>
            ))}
          </div>
          <div className="section">
            <div className="section-body skeleton-facts">
              {[0, 1, 2, 3, 4, 5].map((i) => (
                <span key={i}>
                  <Skeleton width={80} height={10} />
                  <Skeleton width={`${50 + ((i * 17) % 40)}%`} />
                </span>
              ))}
            </div>
          </div>
        </>
      )}
      {variant === "home" && (
        <div className="tiles">
          {[0, 1, 2, 3, 4, 5, 6, 7].map((i) => (
            <span key={i} className="tile skeleton-tile">
              <Skeleton block width={32} height={32} />
              <Skeleton width="60%" />
              <Skeleton width={40} height={28} />
            </span>
          ))}
        </div>
      )}
      {variant !== "detail" && (
        <ul className="list skeleton-list">
          {rows.slice(0, variant === "home" ? 4 : rows.length).map((w, i) => (
            <li key={i} className="row">
              <span className="row-main">
                <span className="row-icon">
                  <Skeleton block width={24} height={24} />
                </span>
                <span className="row-text">
                  <Skeleton width={`${w}%`} />
                  <Skeleton width={`${w / 2}%`} height={10} />
                </span>
                <span className="row-meta">
                  <Skeleton width={56} height={20} />
                </span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

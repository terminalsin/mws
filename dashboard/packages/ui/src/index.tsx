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
import { CommandPalette, NavLink, RegionPicker, ServicesMenu, SideNav, Toasts, type NavGroup } from "./client";
import { zoneHref, type ZoneId } from "./zones";

export { ActionForm, CommandPalette, NavLink, RegionPicker, Sheet, Toasts, type ActionResult, type FormAction, type SearchHit } from "./client";
export { CATEGORIES, SERVICES, iconUrl, navigation, runtimeIcon, service, type Category, type CategoryId, type NavItem, type Service } from "./catalog";
export { ZONES, zone, zoneHref, REGION_COOKIE, type Zone, type ZoneId } from "./zones";

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

/** The page chrome every zone renders around its content: one sidebar that
 * spans all zones and a toolbar with search, region and account. */
export function Frame({ zone: current, info, children }: { zone: ZoneId; info: FrameInfo; children: ReactNode }) {
  const groups: NavGroup[] = navigation().map(({ category, services }) => ({
    id: category.id,
    name: category.name,
    services: services.map((s) => ({
      id: s.id,
      short: s.short,
      icon: s.icon,
      zone: s.zone!,
      path: s.path!,
      href: zoneHref(s.zone!, s.path!),
      nav: (s.nav ?? []).map((n) => ({ ...n, href: zoneHref(s.zone!, n.path) })),
    })),
  }));
  const home = current === "shell" ? <Link className="brand" href="/" aria-label="MWS home">{brand}</Link> : <a className="brand" href="/" aria-label="MWS home">{brand}</a>;
  return (
    <Toasts>
      <div className="frame">
        <header className="topbar">
          {home}
          <ServicesMenu groups={groups} />
          <CommandPalette />
          <div className="topbar-end">
            <span className={info.error ? "health down" : "health up"} title={info.error ? `MWS unreachable at ${info.endpoint}` : `MWS at ${info.endpoint}`} />
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
              <SideNav zone={current} groups={groups} />
            </Suspense>
            <div className="nav-foot">
              <NavLink {...(current === "shell" ? { href: "/control", zonePath: "/control", sameZone: true } : { href: "/control", sameZone: false })} icon={<SlidersHorizontal size={17} aria-hidden />}>
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
    <span className="brand-mark" aria-hidden>
      M
    </span>
    <span className="brand-name">MWS</span>
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
            {subtitle && <div className="subtitle">{subtitle}</div>}
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
  /** Link across zones (full document load). */
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

/** A status as a colored dot with its word. */
export function Status({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span className={`status ${tone}`}>
      <span className="dot" aria-hidden />
      {children}
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
      <div className={`metric-value ${tone ?? ""}`}>{value}</div>
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

/** A segmented control of links (Apple-style tabs). */
export function Segments({ items, label }: { items: { label: ReactNode; href: string; active: boolean; count?: number }[]; label?: string }) {
  return (
    <nav className="segments" aria-label={label}>
      {items.map((t) => (
        <Link key={t.href} href={t.href} className={t.active ? "segment active" : "segment"} aria-current={t.active ? "page" : undefined}>
          {t.label}
          {t.count !== undefined && <span className="count">{t.count}</span>}
        </Link>
      ))}
    </nav>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
      {hint && <span className="field-hint">{hint}</span>}
    </label>
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

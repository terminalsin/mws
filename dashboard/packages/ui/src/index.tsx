import Link from "next/link";
import type { ReactNode } from "react";

import { NavLink, RegionPicker } from "./client";
import { ZONES, zoneHref, type ZoneId } from "./zones";

export { ActionForm, NavLink, RegionPicker, type ActionResult, type FormAction } from "./client";
export { ZONES, zone, zoneHref, REGION_COOKIE, type Zone, type ZoneId, type NavItem } from "./zones";

export interface FrameInfo {
  endpoint: string;
  region: string;
  /** The caller's account, or null when MWS could not be reached. */
  account: string | null;
  principal: string | null;
  error: string | null;
}

/** The page chrome every zone renders around its content: one sidebar that
 * spans all zones, and a top bar with the endpoint, account and region. */
export function Frame({ zone: current, info, children }: { zone: ZoneId; info: FrameInfo; children: ReactNode }) {
  return (
    <div className="frame">
      <aside className="sidebar">
        <a className="brand" href="/">
          <span className="brand-mark" aria-hidden>
            M
          </span>
          <span>
            <strong>MWS</strong>
            <small>console</small>
          </span>
        </a>
        <nav aria-label="Services">
          {ZONES.map((z) => (
            <div key={z.id} className={z.id === current ? "nav-group current" : "nav-group"}>
              {z.id !== "shell" && <div className="nav-title">{z.title}</div>}
              {z.nav.map((item) => (
                <NavLink
                  key={item.path}
                  sameZone={z.id === current}
                  href={z.id === current ? item.path : zoneHref(z.id, item.path)}
                >
                  {item.label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="endpoint" title="Where the console sends its AWS SDK calls">
            <span className={info.error ? "dot down" : "dot up"} aria-hidden />
            <code>{info.endpoint}</code>
          </div>
          <div className="identity">
            {info.account && (
              <span title={info.principal ?? undefined}>
                Account <code>{info.account}</code>
              </span>
            )}
            <RegionPicker region={info.region} />
          </div>
        </header>
        {info.error && (
          <div className="banner error">
            MWS is not reachable at <code>{info.endpoint}</code>: {info.error}. Start it with{" "}
            <code>cargo run -p mws</code>.
          </div>
        )}
        <main className="content">{children}</main>
      </div>
    </div>
  );
}

export function PageHeader({
  title,
  description,
  crumbs,
  actions,
}: {
  title: ReactNode;
  description?: ReactNode;
  crumbs?: { label: string; href: string }[];
  actions?: ReactNode;
}) {
  return (
    <div className="page-header">
      {crumbs && crumbs.length > 0 && (
        <nav className="crumbs" aria-label="Breadcrumb">
          {crumbs.map((c) => (
            <span key={c.href}>
              <Link href={c.href}>{c.label}</Link>
              <span aria-hidden> / </span>
            </span>
          ))}
        </nav>
      )}
      <div className="page-title">
        <h1>{title}</h1>
        {actions && <div className="page-actions">{actions}</div>}
      </div>
      {description && <p className="muted">{description}</p>}
    </div>
  );
}

export function Section({ title, actions, children }: { title?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="section">
      {(title || actions) && (
        <div className="section-head">
          {title && <h2>{title}</h2>}
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

export interface Column<T> {
  header: ReactNode;
  cell: (row: T) => ReactNode;
  className?: string;
}

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
  if (rows.length === 0) return <Empty>{empty ?? "Nothing here yet."}</Empty>;
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

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export type Tone = "neutral" | "good" | "warn" | "bad" | "info";

export function Badge({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

export function KeyValue({ items }: { items: [ReactNode, ReactNode][] }) {
  return (
    <dl className="kv">
      {items.map(([k, v], i) => (
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

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint && <div className="stat-hint muted">{hint}</div>}
    </div>
  );
}

export function Tabs({ items }: { items: { label: string; href: string; active: boolean; count?: number }[] }) {
  return (
    <nav className="tabs">
      {items.map((t) => (
        <Link key={t.href} href={t.href} className={t.active ? "tab active" : "tab"}>
          {t.label}
          {t.count !== undefined && <span className="count">{t.count}</span>}
        </Link>
      ))}
    </nav>
  );
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: ReactNode;
  children: ReactNode;
}) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
      {hint && <span className="field-hint muted">{hint}</span>}
    </label>
  );
}

export function Grid({ children }: { children: ReactNode }) {
  return <div className="grid">{children}</div>;
}

export function Card({ title, href, children }: { title: ReactNode; href?: string; children?: ReactNode }) {
  const body = (
    <>
      <div className="card-title">{title}</div>
      {children && <div className="card-body">{children}</div>}
    </>
  );
  return href ? (
    <a className="card link" href={href}>
      {body}
    </a>
  ) : (
    <div className="card">{body}</div>
  );
}

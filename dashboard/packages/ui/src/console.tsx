"use client";

// A terminal and a file explorer for compute resources. The zone passes the
// server actions (from @mws-dashboard/aws/shell-actions) and the target.
import { ArrowUp, Download, File, FileSymlink, Folder, FolderPlus, RefreshCw, Trash2, Upload, X } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type KeyboardEvent } from "react";

import { DotMatrix } from "./loaders";
import { Asciify } from "./motion";

export interface ShellTarget {
  service: "ec2" | "ecs";
  base: string;
}

interface ExecResult {
  ok: boolean;
  stdout: string;
  stderr: string;
  exitCode: number;
  cwd?: string;
  error?: string;
}

interface FileEntry {
  name: string;
  type: "file" | "dir" | "link";
  size: number;
  modified: number;
  mode: string;
}

type Listing = { ok: true; path: string; entries: FileEntry[] } | { ok: false; error: string };
type FileData = { ok: true; base64: string; size: number; truncated: boolean } | { ok: false; error: string };
type Done = { ok: true } | { ok: false; error: string };

export interface ShellActions {
  exec: (t: ShellTarget, command: string, cwd?: string) => Promise<ExecResult>;
  list: (t: ShellTarget, path: string) => Promise<Listing>;
  read: (t: ShellTarget, path: string) => Promise<FileData>;
  write: (t: ShellTarget, path: string, base64: string) => Promise<Done>;
  remove: (t: ShellTarget, path: string) => Promise<Done>;
  mkdir: (t: ShellTarget, path: string) => Promise<Done>;
}

interface Line {
  kind: "in" | "out" | "err";
  text: string;
}

/** A command-at-a-time terminal: `cd` carries over, ↑/↓ walk history, Ctrl+L clears. */
export function Terminal({ target, actions, user = "root", host }: { target: ShellTarget; actions: Pick<ShellActions, "exec">; user?: string; host: string }) {
  const [lines, setLines] = useState<Line[]>([]);
  const [cwd, setCwd] = useState<string | undefined>(undefined);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [cursor, setCursor] = useState(-1);
  const screen = useRef<HTMLDivElement>(null);
  const field = useRef<HTMLInputElement>(null);

  useEffect(() => {
    screen.current?.scrollTo({ top: screen.current.scrollHeight });
  }, [lines, busy]);

  // Learn the starting directory.
  useEffect(() => {
    actions.exec(target, "true").then((r) => r.ok && setCwd(r.cwd));
  }, [actions, target]);

  const prompt = `${user}@${host}:${cwd ?? "~"}#`;
  const run = useCallback(
    async (command: string) => {
      setLines((l) => [...l, { kind: "in", text: `${prompt} ${command}` }]);
      if (command.trim() === "clear") {
        setLines([]);
        return;
      }
      setBusy(true);
      const r = await actions.exec(target, command, cwd);
      setBusy(false);
      if (!r.ok) {
        setLines((l) => [...l, { kind: "err", text: r.error ?? "failed" }]);
        return;
      }
      setLines((l) => [
        ...l,
        ...(r.stdout ? [{ kind: "out" as const, text: r.stdout }] : []),
        ...(r.stderr ? [{ kind: "err" as const, text: r.stderr.replace(/\n$/, "") }] : []),
      ]);
      if (r.cwd) setCwd(r.cwd);
    },
    [actions, target, cwd, prompt],
  );

  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && !busy) {
      const cmd = input;
      setInput("");
      setCursor(-1);
      if (cmd.trim()) setHistory((h) => [cmd, ...h.filter((x) => x !== cmd)].slice(0, 100));
      void run(cmd);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      const next = Math.min(cursor + 1, history.length - 1);
      if (next >= 0) {
        setCursor(next);
        setInput(history[next]);
      }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      const next = cursor - 1;
      setCursor(Math.max(next, -1));
      setInput(next >= 0 ? history[next] : "");
    } else if (e.key === "l" && e.ctrlKey) {
      e.preventDefault();
      setLines([]);
    }
  };

  return (
    <div className="terminal" ref={screen} onClick={() => field.current?.focus()} data-testid="terminal" data-state={busy ? "running" : "ready"}>
      {lines.map((l, i) => (
        <pre key={i} className={`terminal-line ${l.kind}`}>
          {l.text}
        </pre>
      ))}
      <label className="terminal-input">
        <span className="terminal-prompt">{prompt}</span>
        <input
          ref={field}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKey}
          aria-label="Command"
          spellCheck={false}
          autoComplete="off"
          autoFocus
          disabled={busy}
        />
        {busy && <DotMatrix pattern="orbit" label="Running" />}
      </label>
    </div>
  );
}

const join = (dir: string, name: string) => (dir.endsWith("/") ? dir : `${dir}/`) + name;
const parent = (p: string) => p.replace(/\/[^/]+\/?$/, "") || "/";

function size(n: number) {
  if (n < 1024) return `${n} B`;
  const u = ["KiB", "MiB", "GiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`;
}

const IMAGE = /\.(png|jpe?g|gif|webp|svg|ico)$/i;
const MIME: Record<string, string> = {
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  svg: "image/svg+xml",
  ico: "image/x-icon",
};

function bytesOf(b64: string) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function base64Of(file: Blob) {
  const buf = new Uint8Array(await file.arrayBuffer());
  let bin = "";
  for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode(...buf.subarray(i, i + 0x8000));
  return btoa(bin);
}

/** Browse, preview, download, upload and delete files. */
export function FileExplorer({ target, actions, start = "/" }: { target: ShellTarget; actions: ShellActions; start?: string }) {
  const [path, setPath] = useState(start);
  const [entries, setEntries] = useState<FileEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<{
    name: string;
    path: string;
    data: FileData;
  } | null>(null);
  const upload = useRef<HTMLInputElement>(null);

  const refresh = useCallback(
    async (p: string) => {
      setBusy(true);
      const r = await actions.list(target, p);
      setBusy(false);
      if (r.ok) {
        setPath(r.path);
        setEntries(r.entries);
        setError(null);
      } else setError(r.error);
    },
    [actions, target],
  );

  useEffect(() => {
    void refresh(start);
  }, [refresh, start]);

  const crumbs = path.split("/").filter(Boolean);
  const view = async (e: FileEntry) => {
    const p = join(path, e.name);
    if (e.type === "dir") return refresh(p);
    setBusy(true);
    const data = await actions.read(target, p);
    setBusy(false);
    setOpen({ name: e.name, path: p, data });
  };
  const download = (name: string, b64: string) => {
    const url = URL.createObjectURL(new Blob([bytesOf(b64)]));
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  };
  const doUpload = async (files: FileList | null) => {
    if (!files?.length) return;
    setBusy(true);
    for (const f of Array.from(files)) {
      const r = await actions.write(target, join(path, f.name), await base64Of(f));
      if (!r.ok) setError(r.error);
    }
    await refresh(path);
  };
  const doDelete = async (e: FileEntry) => {
    if (!confirm(`Delete ${join(path, e.name)}?`)) return;
    setBusy(true);
    const r = await actions.remove(target, join(path, e.name));
    if (!r.ok) setError(r.error);
    await refresh(path);
  };
  const doMkdir = async () => {
    const name = prompt("Folder name");
    if (!name) return;
    setBusy(true);
    const r = await actions.mkdir(target, join(path, name));
    if (!r.ok) setError(r.error);
    await refresh(path);
  };

  let preview: React.ReactNode = null;
  if (open?.data.ok) {
    const bytes = bytesOf(open.data.base64);
    const ext = open.name.split(".").pop()?.toLowerCase() ?? "";
    if (IMAGE.test(open.name)) {
      preview = <Asciify className="file-image" alt={open.name} src={`data:${MIME[ext] ?? "image/png"};base64,${open.data.base64}`} />;
    } else {
      const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(0, 512 * 1024));
      const binary = bytes.subarray(0, 4096).some((b) => b === 0);
      preview = binary ? <span className="muted">Binary · {size(open.data.size)}</span> : <pre className="code file-text">{text}</pre>;
    }
  }

  return (
    <div className="explorer" data-testid="file-explorer">
      <div className="explorer-bar">
        <button type="button" className="icon-button" aria-label="Up" title="Up" disabled={path === "/"} onClick={() => refresh(parent(path))}>
          <ArrowUp size={15} />
        </button>
        <nav className="crumbs" aria-label="Path">
          <button type="button" onClick={() => refresh("/")}>
            /
          </button>
          {crumbs.map((c, i) => (
            <button key={i} type="button" onClick={() => refresh("/" + crumbs.slice(0, i + 1).join("/"))}>
              {c}
            </button>
          ))}
        </nav>
        {busy && <DotMatrix pattern="twinkle" label="Loading" />}
        <button type="button" className="icon-button" aria-label="Refresh" title="Refresh" onClick={() => refresh(path)}>
          <RefreshCw size={15} />
        </button>
        <button type="button" className="icon-button" aria-label="New folder" title="New folder" onClick={doMkdir}>
          <FolderPlus size={15} />
        </button>
        <button type="button" className="icon-button primary" aria-label="Upload" title="Upload" onClick={() => upload.current?.click()}>
          <Upload size={15} />
        </button>
        <input ref={upload} type="file" multiple hidden onChange={(e) => doUpload(e.target.files)} data-testid="upload" />
      </div>
      {error && (
        <div className="banner error" role="alert">
          {error}
        </div>
      )}
      {!entries && !error && (
        <ul className="list skeleton-list" aria-hidden>
          {[46, 30, 58, 38, 50].map((w, i) => (
            <li key={i} className="row">
              <span className="row-main">
                <span className="row-icon">
                  <span className="skeleton-block" style={{ width: 18, height: 18 }} />
                </span>
                <span className="row-text">
                  <span className="skeleton-line" style={{ width: `${w}%` }} />
                </span>
              </span>
            </li>
          ))}
        </ul>
      )}
      {entries && (
        <ul className="list explorer-list" aria-label="Files" aria-busy={busy} data-busy={busy || undefined} key={path}>
          {entries.map((e) => {
            const Icon = e.type === "dir" ? Folder : e.type === "link" ? FileSymlink : File;
            return (
              <li key={e.name} className="row">
                <button type="button" className="row-main explorer-item" onClick={() => view(e)}>
                  <span className="row-icon">
                    <Icon size={18} className={e.type === "dir" ? "folder" : undefined} aria-hidden />
                  </span>
                  <span className="row-text">
                    <span className="row-title">{e.name}</span>
                  </span>
                  <span className="row-meta">
                    {e.type !== "dir" && <span>{size(e.size)}</span>}
                    {e.modified > 0 && <span>{new Date(e.modified * 1000).toLocaleString()}</span>}
                    <code>{e.mode}</code>
                  </span>
                </button>
                <span className="row-actions">
                  <button type="button" className="icon-button" aria-label={`Delete ${e.name}`} title="Delete" onClick={() => doDelete(e)}>
                    <Trash2 size={15} />
                  </button>
                </span>
              </li>
            );
          })}
          {entries.length === 0 && <li className="row muted explorer-empty">Empty</li>}
        </ul>
      )}
      {open && (
        <div className="file-preview" role="dialog" aria-label={open.path}>
          <div className="explorer-bar">
            <code className="clip">{open.path}</code>
            {open.data.ok && (
              <button
                type="button"
                className="icon-button"
                aria-label="Download"
                title="Download"
                onClick={() => open.data.ok && download(open.name, open.data.base64)}
              >
                <Download size={15} />
              </button>
            )}
            <button type="button" className="icon-button" aria-label="Close" title="Close" onClick={() => setOpen(null)}>
              <X size={15} />
            </button>
          </div>
          {open.data.ok ? preview : <div className="banner error">{open.data.error}</div>}
          {open.data.ok && open.data.truncated && (
            <span className="muted">
              First {size(bytesOf(open.data.base64).length)} of {size(open.data.size)}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

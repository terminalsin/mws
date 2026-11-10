"use client";

// Motion components. Each one animates a change of state (a tab moving, a
// number changing, a check confirming) and never an element merely
// appearing: see the motion rules in styles.css.
import Link from "next/link";
import { useEffect, useLayoutEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";

const reduced = () => typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/** Line tabs whose indicator slides to the chosen tab. It moves on the
 * click, before the next page arrives, so the choice registers at once. */
export function Segments({ items, label }: { items: { label: ReactNode; href: string; active: boolean; count?: number }[]; label?: string }) {
  const nav = useRef<HTMLElement>(null);
  const [chosen, setChosen] = useState<string | null>(null);
  const [box, setBox] = useState<{ x: number; y: number; w: number } | null>(null);
  const [ready, setReady] = useState(false);
  const active = items.find((t) => t.active)?.href;
  // The page caught up with the click: follow the page again.
  useEffect(() => setChosen(null), [active]);
  const target = chosen ?? active;

  useLayoutEffect(() => {
    const measure = () => {
      const el = target ? nav.current?.querySelector<HTMLElement>(`[data-href="${CSS.escape(target)}"]`) : null;
      setBox(el ? { x: el.offsetLeft, y: el.offsetTop + el.offsetHeight - 2, w: el.offsetWidth } : null);
    };
    measure();
    // Tabs change width without the bar doing so (a count arriving), so
    // watch each tab as well as the bar.
    const observer = new ResizeObserver(measure);
    if (nav.current) for (const el of [nav.current, ...nav.current.querySelectorAll<HTMLElement>("[data-href]")]) observer.observe(el);
    return () => observer.disconnect();
  }, [target, items.length]);
  // Place the indicator first, then let it move: no slide in from 0 on load.
  useEffect(() => {
    if (!box || ready) return;
    const frame = requestAnimationFrame(() => setReady(true));
    return () => cancelAnimationFrame(frame);
  }, [box, ready]);

  return (
    <nav className="segments" aria-label={label} ref={nav} data-ready={(ready && !!box) || undefined}>
      {items.map((t) => (
        <Link
          key={t.href}
          href={t.href}
          data-href={t.href}
          className={t.active ? "segment active" : "segment"}
          aria-current={t.active ? "page" : undefined}
          data-chosen={target === t.href || undefined}
          onClick={(e) => {
            if (!e.metaKey && !e.ctrlKey && !e.shiftKey && e.button === 0) setChosen(t.href);
          }}
        >
          {t.label}
          {t.count !== undefined && <span className="count">{t.count}</span>}
        </Link>
      ))}
      {box && <span className="segment-indicator" aria-hidden style={{ transform: `translate(${box.x}px, ${box.y}px)`, width: box.w }} />}
    </nav>
  );
}

function format(value: number) {
  const decimals = Number.isInteger(value) ? 0 : Math.min(2, (String(value).split(".")[1] ?? "").length);
  return value.toLocaleString(undefined, { minimumFractionDigits: decimals, maximumFractionDigits: decimals });
}

/** A number whose changed digits cross-fade in place when it changes (after
 * an action refreshes the page): rising when it went up, falling when it went
 * down. Unchanged digits hold still, so the eye lands on what changed. The
 * first render shows the value as-is. */
export function CountUp({ value }: { value: number }) {
  const text = format(value);
  const previous = useRef({ text, value });
  const [change, setChange] = useState<{ from: string; to: string; up: boolean; n: number } | null>(null);
  useEffect(() => {
    const last = previous.current;
    if (last.text === text) return;
    previous.current = { text, value };
    if (reduced()) return;
    setChange((c) => ({ from: last.text, to: text, up: value >= last.value, n: (c?.n ?? 0) + 1 }));
    const timer = setTimeout(() => setChange(null), 600);
    return () => clearTimeout(timer);
  }, [text, value]);

  if (!change || change.to !== text) return <>{text}</>;
  const sameShape = change.from.length === text.length;
  return (
    <span className="number-change" data-dir={change.up ? "up" : "down"} aria-label={text}>
      {sameShape ? (
        [...text].map((ch, i) =>
          ch === change.from[i] ? (
            <span key={i} aria-hidden>
              {ch}
            </span>
          ) : (
            <span key={`${change.n}-${i}`} className="digit" aria-hidden>
              <span className="digit-out">{change.from[i]}</span>
              <span className="digit-in">{ch}</span>
            </span>
          ),
        )
      ) : (
        <span key={change.n} className="digit" aria-hidden>
          <span className="digit-in">{text}</span>
        </span>
      )}
    </span>
  );
}

/** A check that draws itself: what a spinner turns into when work succeeds. */
export function CheckMark({ size = 15 }: { size?: number }) {
  return (
    <svg className="checkmark" viewBox="0 0 24 24" width={size} height={size} fill="none" stroke="currentColor" strokeWidth={2.4} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M20 6 9 17l-5-5" pathLength={1} />
    </svg>
  );
}

// Asciify: under the pointer, an image is redrawn as characters. After
// canvasui.dev's Asciify (its 5×5 glyph ramp), on a 2D canvas: a lens chases
// the pointer by exponential approach and closes when the pointer leaves, so
// nothing runs until someone points at the image.

/** 5×5 glyphs, dark to bright, packed row by row from the top-left bit. */
const RAMP = [0, 128, 131200, 14336, 459200, 469440, 4357252, 18157905, 11512810, 15724526];
const GLYPH = 5;

export function Asciify({
  src,
  alt,
  className,
  radius = 90,
  scale = 2,
  spacing = 1,
}: {
  src: string;
  alt: string;
  className?: string;
  /** Lens radius in CSS pixels. */
  radius?: number;
  /** CSS pixels per glyph pixel. */
  scale?: number;
  /** Empty glyph pixels between characters. */
  spacing?: number;
}) {
  const image = useRef<HTMLImageElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const state = useRef({
    frame: 0,
    target: { x: 0, y: 0, r: 0 },
    lens: { x: 0, y: 0, r: 0 },
    cells: null as null | { cols: number; rows: number; data: Uint8ClampedArray; cell: number; w: number; h: number },
  });

  const sample = () => {
    const img = image.current;
    if (!img || !img.complete || !img.naturalWidth) return null;
    const w = img.clientWidth;
    const h = img.clientHeight;
    const cell = (GLYPH + spacing) * scale;
    const cols = Math.max(1, Math.floor(w / cell));
    const rows = Math.max(1, Math.floor(h / cell));
    const off = document.createElement("canvas");
    off.width = cols;
    off.height = rows;
    const ctx = off.getContext("2d", { willReadFrequently: true });
    if (!ctx) return null;
    ctx.drawImage(img, 0, 0, cols, rows);
    try {
      return { cols, rows, cell, w, h, data: ctx.getImageData(0, 0, cols, rows).data };
    } catch {
      return null; // a cross-origin image without CORS cannot be read
    }
  };

  const draw = () => {
    const s = state.current;
    const out = canvas.current;
    if (!out) return;
    const k = reduced() ? 1 : 0.18;
    s.lens.x += (s.target.x - s.lens.x) * k;
    s.lens.y += (s.target.y - s.lens.y) * k;
    s.lens.r += (s.target.r - s.lens.r) * k;
    const c = s.cells ?? (s.cells = sample());
    const ctx = out.getContext("2d");
    if (!c || !ctx) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    if (out.width !== Math.round(c.w * dpr)) {
      out.width = Math.round(c.w * dpr);
      out.height = Math.round(c.h * dpr);
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, c.w, c.h);
    const { x, y, r } = s.lens;
    if (r > 0.5) {
      const px = scale;
      const paper = getComputedStyle(out).getPropertyValue("--surface").trim() || "#ffffff";
      for (let row = 0; row < c.rows; row++) {
        for (let col = 0; col < c.cols; col++) {
          const cx = col * c.cell + c.cell / 2;
          const cy = row * c.cell + c.cell / 2;
          const d = Math.hypot(cx - x, cy - y);
          if (d > r) continue;
          // Feathered edge: cells thin out toward the rim of the lens.
          const coverage = Math.min(1, (r - d) / (r * 0.35));
          if (((col * 73856093) ^ (row * 19349663)) % 1000 >= coverage * 1000) continue;
          const o = (row * c.cols + col) * 4;
          const [red, green, blue] = [c.data[o], c.data[o + 1], c.data[o + 2]];
          const light = (0.2126 * red + 0.7152 * green + 0.0722 * blue) / 255;
          // Ink on paper: darker pixels take denser characters, in their own
          // colour, so the image still reads through the type.
          // Contrast: faint detail (text on a light page) still gets a character.
          const ink = Math.min(1, Math.sqrt(1 - light) * 1.6);
          const glyph = RAMP[Math.min(RAMP.length - 1, Math.round(ink * (RAMP.length - 1)))];
          const left = col * c.cell;
          const top = row * c.cell;
          ctx.fillStyle = paper;
          ctx.fillRect(left, top, c.cell, c.cell);
          ctx.fillStyle = `rgb(${red * 0.7}, ${green * 0.7}, ${blue * 0.7})`;
          for (let bit = 0; bit < GLYPH * GLYPH; bit++) {
            if (glyph & (1 << (GLYPH * GLYPH - 1 - bit))) {
              ctx.fillRect(left + (spacing / 2 + (bit % GLYPH)) * px, top + (spacing / 2 + Math.floor(bit / GLYPH)) * px, px, px);
            }
          }
        }
      }
    }
    const settled = Math.abs(s.target.r - s.lens.r) < 0.5 && Math.hypot(s.target.x - s.lens.x, s.target.y - s.lens.y) < 0.5;
    s.frame = settled ? 0 : requestAnimationFrame(draw);
  };

  const run = () => {
    if (!state.current.frame) state.current.frame = requestAnimationFrame(draw);
  };

  useEffect(() => {
    const s = state.current;
    return () => cancelAnimationFrame(s.frame);
  }, []);

  return (
    <span
      className="asciify"
      onPointerMove={(e) => {
        const box = e.currentTarget.getBoundingClientRect();
        const s = state.current;
        const x = e.clientX - box.left;
        const y = e.clientY - box.top;
        if (s.target.r === 0 && s.lens.r < 1) Object.assign(s.lens, { x, y });
        Object.assign(s.target, { x, y, r: radius });
        run();
      }}
      onPointerLeave={() => {
        state.current.target.r = 0;
        run();
      }}
    >
      <img
        ref={image}
        src={src}
        alt={alt}
        className={className}
        onLoad={() => {
          state.current.cells = null;
        }}
      />
      <canvas ref={canvas} aria-hidden style={{ width: "100%", height: "100%" } as CSSProperties} />
    </span>
  );
}

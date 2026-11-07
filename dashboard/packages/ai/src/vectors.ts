// Pure vector and text helpers, free of I/O so they can be unit tested.

export type Vector = Float32Array;

export function cosine(a: Vector, b: Vector): number {
  let dot = 0;
  let na = 0;
  let nb = 0;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  return na && nb ? dot / Math.sqrt(na * nb) : 0;
}

/** Split identifiers the way people read them: "ordersApi-prod_dlq" ->
 * ["orders", "api", "prod", "dlq"]. */
export function tokens(text: string): string[] {
  return text
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 0);
}

/** A deterministic, offline embedding: hashed word and character-trigram
 * features. Similar names and words land close together; it knows nothing of
 * meaning, which is what a real model adds. */
export function lexicalEmbedding(text: string, dims = 512): Vector {
  const v = new Float32Array(dims);
  const add = (feature: string, weight: number) => {
    let h = 2166136261;
    for (let i = 0; i < feature.length; i++) h = Math.imul(h ^ feature.charCodeAt(i), 16777619);
    const sign = h & 1 ? 1 : -1;
    v[(h >>> 1) % dims] += sign * weight;
  };
  for (const word of tokens(text)) {
    add(`w:${word}`, 2);
    const padded = `^${word}$`;
    for (let i = 0; i + 3 <= padded.length; i++) add(`t:${padded.slice(i, i + 3)}`, 1);
  }
  let norm = 0;
  for (const x of v) norm += x * x;
  norm = Math.sqrt(norm) || 1;
  for (let i = 0; i < dims; i++) v[i] /= norm;
  return v;
}

/** How well the query's words are covered by the text: each query token
 * scores 1 for a whole-word match, 0.7 for a prefix match. */
export function keywordScore(query: string, text: string): number {
  const q = tokens(query);
  if (q.length === 0) return 0;
  const words = tokens(text);
  const haystack = text.toLowerCase();
  let total = 0;
  for (const t of q) {
    if (words.includes(t)) total += 1;
    else if (words.some((w) => w.startsWith(t))) total += 0.7;
    else if (t.length >= 3 && haystack.includes(t)) total += 0.5;
  }
  return total / q.length;
}

export interface Clustered<T> {
  members: T[];
  /** The tokens most members share, as a label. */
  label: string;
}

/** Greedy agglomerative grouping by cosine similarity: each item joins the
 * closest existing group whose centroid is at least `threshold` similar. */
export function cluster<T>(items: T[], vectors: Vector[], text: (item: T) => string, threshold = 0.55): Clustered<T>[] {
  const groups: { members: T[]; sum: Float32Array }[] = [];
  items.forEach((item, i) => {
    const v = vectors[i];
    let best = -1;
    let bestScore = threshold;
    groups.forEach((g, gi) => {
      const s = cosine(v, g.sum);
      if (s >= bestScore) {
        best = gi;
        bestScore = s;
      }
    });
    if (best >= 0) {
      groups[best].members.push(item);
      for (let d = 0; d < v.length; d++) groups[best].sum[d] += v[d];
    } else {
      groups.push({ members: [item], sum: Float32Array.from(v) });
    }
  });
  return groups.map((g) => ({ members: g.members, label: sharedLabel(g.members.map(text)) }));
}

const STOP = new Set(["the", "a", "an", "of", "and", "aws", "arn", "service", "role", "function", "queue", "topic", "bucket"]);

/** The words shared by most of the texts, in the order they appear. */
export function sharedLabel(texts: string[]): string {
  if (texts.length === 0) return "";
  const counts = new Map<string, number>();
  for (const t of texts) for (const w of new Set(tokens(t))) if (!STOP.has(w) && !/^\d+$/.test(w)) counts.set(w, (counts.get(w) ?? 0) + 1);
  const need = Math.max(1, Math.ceil(texts.length * 0.6));
  const first = tokens(texts[0]);
  const shared = first.filter((w, i) => (counts.get(w) ?? 0) >= need && first.indexOf(w) === i);
  return shared.slice(0, 3).join(" ");
}

export type Environment = "production" | "staging" | "development" | "test";

/** The deployment stage a name or tag set implies, if any. */
export function environment(text: string): Environment | null {
  const t = tokens(text);
  const has = (...w: string[]) => w.some((x) => t.includes(x));
  if (has("prod", "production", "prd", "live")) return "production";
  if (has("staging", "stage", "stg", "preprod", "uat")) return "staging";
  if (has("dev", "development", "sandbox", "local")) return "development";
  if (has("test", "tests", "testing", "qa", "e2e", "ci")) return "test";
  return null;
}

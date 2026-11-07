// The console's curation layer. Pages hand it resources; it ranks them
// against a query, sorts them into sections and finds the applications they
// belong to.
//
// Embeddings come from Amazon Bedrock. By default that is MWS's own Bedrock,
// so curation works offline and without keys (MWS's built-in model answers
// with lexical embeddings; set MWS_BEDROCK_BACKEND on MWS for a real model).
// MWS_DASHBOARD_AI picks another source:
//   bedrock  (default) Bedrock at MWS_DASHBOARD_AI_ENDPOINT, or MWS
//   aws      real Amazon Bedrock with the default AWS credential chain
//   local    an in-process model (npm i @huggingface/transformers)
//   lexical  hashed words and trigrams, no service at all
import "server-only";

import { BedrockRuntimeClient, InvokeModelCommand } from "@aws-sdk/client-bedrock-runtime";
import { credentials, endpoint } from "@mws-dashboard/aws";

import { cluster, cosine, environment, keywordScore, lexicalEmbedding, sharedLabel, tokens, type Vector } from "./vectors";

export { cosine, environment, keywordScore, sharedLabel, tokens, type Environment, type Vector } from "./vectors";

const MODEL = process.env.MWS_DASHBOARD_EMBED_MODEL ?? "amazon.titan-embed-text-v2:0";
const DIMS = 512;
const CACHE_LIMIT = 20_000;
const cache = new Map<string, Vector>();
let warned = false;

type Embedder = (texts: string[]) => Promise<Vector[]>;

function bedrockEmbedder(real: boolean): Embedder {
  const client = new BedrockRuntimeClient(
    real
      ? { region: process.env.MWS_DASHBOARD_AI_REGION ?? process.env.AWS_REGION ?? "us-east-1" }
      : {
          endpoint: process.env.MWS_DASHBOARD_AI_ENDPOINT ?? endpoint(),
          region: process.env.MWS_DASHBOARD_AI_REGION ?? "us-east-1",
          credentials: credentials(),
          maxAttempts: 1,
        },
  );
  const one = async (text: string): Promise<Vector> => {
    const body = MODEL.startsWith("cohere.")
      ? { texts: [text.slice(0, 2000)], input_type: "search_document" }
      : { inputText: text.slice(0, 8000), dimensions: DIMS, normalize: true };
    const out = await client.send(
      new InvokeModelCommand({ modelId: MODEL, contentType: "application/json", accept: "application/json", body: JSON.stringify(body) }),
    );
    const parsed = JSON.parse(new TextDecoder().decode(out.body));
    return Float32Array.from(parsed.embedding ?? parsed.embeddings?.[0] ?? parsed.embeddings?.float?.[0]);
  };
  return async (texts) => {
    const out: Vector[] = new Array(texts.length);
    let next = 0;
    const worker = async () => {
      while (next < texts.length) {
        const i = next++;
        out[i] = await one(texts[i]);
      }
    };
    await Promise.all(Array.from({ length: Math.min(16, texts.length) }, worker));
    return out;
  };
}

function localEmbedder(): Embedder {
  // Loaded by name at runtime so the package stays optional.
  const name = "@huggingface/transformers";
  let pipe: Promise<(t: string[], o: object) => Promise<{ tolist(): number[][] }>> | null = null;
  return async (texts) => {
    pipe ??= import(/* webpackIgnore: true */ name).then((m) => m.pipeline("feature-extraction", "Xenova/all-MiniLM-L6-v2"));
    const out = await (await pipe)(texts, { pooling: "mean", normalize: true });
    return out.tolist().map((v) => Float32Array.from(v));
  };
}

const lexical: Embedder = async (texts) => texts.map((t) => lexicalEmbedding(t, DIMS));

function provider(): Embedder {
  switch (process.env.MWS_DASHBOARD_AI ?? "bedrock") {
    case "lexical":
      return lexical;
    case "local":
      return localEmbedder();
    case "aws":
      return bedrockEmbedder(true);
    default:
      return bedrockEmbedder(false);
  }
}

let active: Embedder | null = null;

/** Embed texts, from cache where possible. Falls back to lexical embeddings
 * (and says so once) when the configured source fails. */
export async function embed(texts: string[]): Promise<Vector[]> {
  active ??= provider();
  const missing = [...new Set(texts.filter((t) => !cache.has(t)))];
  if (missing.length) {
    let vectors: Vector[];
    try {
      vectors = await active(missing);
    } catch (e) {
      if (!warned) {
        console.warn(`[ai] embeddings unavailable (${(e as Error).message}); using lexical embeddings`);
        warned = true;
      }
      active = lexical;
      cache.clear();
      return embed(texts);
    }
    if (cache.size + missing.length > CACHE_LIMIT) cache.clear();
    missing.forEach((t, i) => cache.set(t, vectors[i]));
  }
  return texts.map((t) => cache.get(t)!);
}

export interface Searchable {
  /** What the resource is called and anything that describes it. */
  text: string;
}

/** Rank documents for a query: meaning (embeddings) blended with words
 * (exact and prefix matches), so "dead letter" finds "orders-dlq" and
 * "ord" finds "orders-api". */
export async function search<T extends Searchable>(query: string, docs: T[], limit = 30): Promise<(T & { score: number })[]> {
  const q = query.trim();
  if (!q || docs.length === 0) return [];
  const [qv, ...dv] = await embed([q, ...docs.map((d) => d.text)]);
  return docs
    .map((d, i) => {
      const words = keywordScore(q, d.text);
      const meaning = cosine(qv, dv[i]);
      return { ...d, score: 0.45 * meaning + 0.55 * words };
    })
    .filter((d) => d.score > 0.28)
    .sort((a, b) => b.score - a.score)
    .slice(0, limit);
}

export interface Class {
  id: string;
  /** Words that describe members of the class, for the embedding match. */
  prototype: string;
  /** Hard evidence: when it matches, the item is in the class. */
  rule?: RegExp;
}

/** Zero-shot classification: rules first, then the nearest class prototype
 * (when it is similar enough), else null. */
export async function classify<T extends Searchable>(items: T[], classes: Class[], threshold = 0.3): Promise<(string | null)[]> {
  if (items.length === 0) return [];
  const vectors = await embed([...classes.map((c) => c.prototype), ...items.map((i) => i.text)]);
  const protos = vectors.slice(0, classes.length);
  return items.map((item, i) => {
    const ruled = classes.find((c) => c.rule?.test(item.text));
    if (ruled) return ruled.id;
    const v = vectors[classes.length + i];
    let best: string | null = null;
    let bestScore = threshold;
    classes.forEach((c, ci) => {
      const words = keywordScore(c.prototype, item.text) > 0 ? 0.15 : 0;
      const s = cosine(v, protos[ci]) + words;
      if (s > bestScore) {
        best = c.id;
        bestScore = s;
      }
    });
    return best;
  });
}

/** Partition items into labelled sections by a classifier; empty sections
 * are dropped and unclassified items go last, under `rest`. */
export async function sections<T extends Searchable>(
  items: T[],
  classes: (Class & { title: string })[],
  rest = "Other",
): Promise<{ id: string; title: string; items: T[] }[]> {
  const labels = await classify(items, classes);
  const out = classes.map((c) => ({ id: c.id, title: c.title, items: items.filter((_, i) => labels[i] === c.id) }));
  const other = items.filter((_, i) => labels[i] === null);
  return [...out, { id: "other", title: rest, items: other }].filter((s) => s.items.length > 0);
}

export interface Application<T> {
  /** A name for the group: a stack or app tag, or the words members share. */
  name: string;
  members: T[];
}

/** Find the applications resources belong to: members of a CloudFormation
 * stack or tagged with the same app/project first, then names that look
 * alike. Singletons are left out; they belong to no application. */
export async function applications<T extends Searchable & { name: string; tags?: Record<string, string> }>(
  items: T[],
): Promise<Application<T>[]> {
  const tagKeys = ["aws:cloudformation:stack-name", "app", "application", "project", "service", "stack"];
  const tagged = new Map<string, T[]>();
  const loose: T[] = [];
  for (const item of items) {
    const tags = Object.fromEntries(Object.entries(item.tags ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    const key = tagKeys.map((k) => tags[k]).find(Boolean);
    if (key) tagged.set(key, [...(tagged.get(key) ?? []), item]);
    else loose.push(item);
  }
  const groups: Application<T>[] = [...tagged.entries()].map(([name, members]) => ({ name, members }));
  // Names: embeddings of the name's words (not ARNs), with a stricter
  // threshold than search, so only clear families join.
  const names = loose.map((i) => tokens(i.name).filter((t) => !/^\d+$/.test(t) && t.length > 1).join(" "));
  const vectors = await embed(names.map((n) => n || "unnamed"));
  for (const c of cluster(loose, vectors, (i) => i.name, 0.62)) {
    if (c.members.length < 2 || !c.label) continue;
    groups.push({ name: c.label, members: c.members });
  }
  return groups.filter((g) => g.members.length >= 2).sort((a, b) => b.members.length - a.members.length);
}

/** The environment chip for a resource, from its tags or name. */
export function stage(name: string, tags?: Record<string, string>) {
  const tagged = Object.entries(tags ?? {}).find(([k]) => /^(env|environment|stage)$/i.test(k));
  return environment(tagged ? tagged[1] : name);
}


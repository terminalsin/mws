import assert from "node:assert/strict";
import { test } from "node:test";

import { cluster, cosine, environment, keywordScore, lexicalEmbedding, sharedLabel, tokens } from "./vectors.ts";

test("tokens split identifiers", () => {
  assert.deepEqual(tokens("ordersApi-prod_DLQ"), ["orders", "api", "prod", "dlq"]);
});

test("lexical embeddings put similar names close", () => {
  const a = lexicalEmbedding("orders-dead-letter-queue");
  const b = lexicalEmbedding("orders-dlq");
  const c = lexicalEmbedding("website-assets");
  assert.ok(cosine(a, b) > cosine(a, c));
  assert.ok(Math.abs(cosine(a, a) - 1) < 1e-5);
});

test("keyword score rewards whole words and prefixes", () => {
  assert.equal(keywordScore("orders", "orders-api"), 1);
  assert.ok(keywordScore("ord", "orders-api") > 0.5);
  assert.equal(keywordScore("billing", "orders-api"), 0);
});

test("cluster groups by name", () => {
  const names = ["orders-api", "orders-worker", "orders-dlq", "website-assets", "website-logs"];
  const groups = cluster(names, names.map((n) => lexicalEmbedding(n)), (n) => n, 0.3);
  const orders = groups.find((g) => g.members.includes("orders-api"))!;
  assert.ok(orders.members.includes("orders-worker"));
  assert.ok(!orders.members.includes("website-assets"));
  assert.equal(orders.label, "orders");
});

test("shared label and environment", () => {
  assert.equal(sharedLabel(["billing-prod-api", "billing-prod-db"]), "billing prod");
  assert.equal(environment("orders-prod-api"), "production");
  assert.equal(environment("Environment=staging"), "staging");
  assert.equal(environment("orders-api"), null);
});

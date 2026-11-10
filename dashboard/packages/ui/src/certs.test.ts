import assert from "node:assert/strict";
import { test } from "node:test";

import { check, valid, type Rule } from "./validation.ts";

const values = (r: Rule, v: string) => check(v, r)?.repairs.map((x) => x.value) ?? [];

test("lists typed into one field are checked item by item", () => {
  const rule: Rule = { type: "list", maxLength: 3, required: true, item: { type: "string", format: "dnsName" } };
  assert.equal(check("example.com\n*.example.com", rule), null);
  const issue = check("example.com, https://www.example.com/path", rule)!;
  assert.equal(issue.code, "format");
  assert.match(issue.message, /^https:\/\/www\.example\.com\/path: /);
  assert.deepEqual(issue.repairs.map((r) => r.value), ["example.com, www.example.com", "example.com"]);
  assert.match(check("a.com b_c.com x.con", rule)!.message, /\(\+1 more\)$/);
  assert.deepEqual(values(rule, "a.com b_c.com x.con"), ["a.com b-c.com x.com", "a.com"]);
  assert.deepEqual(values(rule, "a.com\nb.com\nc.com\nd.com"), ["a.com\nb.com\nc.com"]);
  assert.equal(check(" , ", rule)?.code, "required");
});

test("DNS names repair pasted URLs, wildcards and typos", () => {
  const rule: Rule = { format: "dnsName" };
  assert.deepEqual(values(rule, "https://Example.com:443/"), ["example.com"]);
  assert.deepEqual(values(rule, "admin@example.com"), ["example.com"]);
  assert.deepEqual(values(rule, "*example.com"), ["*.example.com"]);
  assert.deepEqual(values(rule, "www.*.example.com"), ["*.example.com"]);
  assert.deepEqual(values(rule, "example.con"), ["example.com"]);
  assert.deepEqual(values(rule, "localhost"), ["localhost.com"]);
  assert.equal(check("-a.example.com", rule)?.message, "A label starts or ends with -");
});

test("PEM fields catch swapped, escaped and unwrapped blocks", () => {
  const body = "MIIBszCCAVmgAwIBAgIUQ".repeat(5);
  const cert = `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`;
  const key = `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----\n`;
  assert.equal(check(cert, { format: "certificate" }), null);
  assert.equal(check(cert + cert, { format: "certificates" }), null);
  assert.equal(check(key, { format: "privateKey" }), null);
  assert.equal(check(key, { format: "certificate" })?.message, "This is a private key, not a certificate");
  assert.equal(check(cert, { format: "privateKey" })?.message, "This is a certificate, not its key");
  assert.match(check(key.replace(/PRIVATE KEY/g, "ENCRYPTED PRIVATE KEY"), { format: "privateKey" })!.message, /^Encrypted/);
  assert.deepEqual(values({ format: "certificate" }, cert + cert), [`-----BEGIN CERTIFICATE-----\n${body.match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE-----\n`]);
  assert.deepEqual(values({ format: "certificate" }, cert.replace(/\n/g, "\\n")), [cert]);
  assert.ok(valid(values({ format: "privateKey" }, body)[0], { format: "privateKey" }));
  assert.ok(valid(values({ format: "certificate" }, cert.replace(/-----END CERTIFICATE-----\n/, ""))[0], { format: "certificate" }));
});

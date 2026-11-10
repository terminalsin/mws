import { expect, test, type Page } from "@playwright/test";

import { row, rowAction, submit, unique } from "./helpers";

test("Route 53: create a zone, add and delete a record", async ({ page }) => {
  const domain = `${unique("dash")}.example.com`;
  await page.goto("/route53");
  await submit(page, "create-zone", { name: domain });
  await expect(page.getByRole("heading", { level: 1, name: domain })).toBeVisible();
  await submit(page, "create-record", { name: `www.${domain}`, type: "A", values: "192.0.2.10", ttl: "60" });
  await expect(row(page, "192.0.2.10")).toBeVisible();
  await rowAction(page, "192.0.2.10", /^Delete www/);
  await expect(row(page, "192.0.2.10")).toHaveCount(0);
});

// Inline validation (packages/ui fields + services/route53/lib/records.ts):
// problems show on the field with one-click repairs, before submitting.

async function openSheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field, control: (name: string) => form.locator(`[name="${name}"]`) };
}

/** Open a sheet and unfold its folded fields (MoreFields, by its label). */
async function unfold(page: Page, testId: string, label = "More") {
  const { form } = await openSheet(page, testId);
  await form.locator("summary", { hasText: label }).click();
  return form;
}

test("Route 53 validation: zone names and record values are repaired in place", async ({ page }) => {
  const domain = `${unique("dash-v")}.example.com`;
  await page.goto("/route53");
  let { form, field, control } = await openSheet(page, "create-zone");

  // A pasted URL keeps its host.
  await control("name").fill(`https://${domain.toUpperCase()}/shop?x=1`);
  await control("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "format");
  await field("name").getByRole("button", { name: /Use the domain/ }).click();
  await expect(control("name")).toHaveValue(domain);
  await expect(field("name")).not.toHaveAttribute("data-invalid");
  await form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name: domain })).toBeVisible();

  ({ form, field, control } = await openSheet(page, "create-record"));
  // A bare label is moved into the zone.
  await control("name").fill("www");
  await control("name").blur();
  await expect(field("name")).toContainText(`Not in ${domain}`);
  await field("name").getByRole("button", { name: /Add \./ }).click();
  await expect(control("name")).toHaveValue(`www.${domain}`);

  // Values follow the type: an IPv4 address is no AAAA value...
  await control("type").selectOption("AAAA");
  await control("values").fill("192.0.2.10");
  await control("values").blur();
  await expect(field("values")).toContainText("belongs in an A record");
  // ...TXT with spaces gets quotes...
  await control("type").selectOption("TXT");
  await control("values").fill("hello world");
  await field("values").getByRole("button", { name: /Add quotes/ }).click();
  await expect(control("values")).toHaveValue('"hello world"');
  // ...and comma-separated addresses go one per line.
  await control("type").selectOption("A");
  await control("values").fill("192.0.2.10, 192.0.2.11");
  await expect(field("values")).toHaveAttribute("data-invalid", "format");
  await field("values").getByRole("button", { name: /Split into lines/ }).click();
  await expect(control("values")).toHaveValue("192.0.2.10\n192.0.2.11");
  await expect(field("values")).not.toHaveAttribute("data-invalid");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, "192.0.2.10, 192.0.2.11")).toBeVisible();

  // Route 53's own rejection (a CNAME beside the A record) lands on the
  // field it concerns, not under the form.
  ({ form, field, control } = await openSheet(page, "create-record"));
  await control("name").fill(`www.${domain}`);
  await control("type").selectOption("CNAME");
  await control("values").fill("app.example.net");
  await form.locator('button[type="submit"]').click();
  await expect(field("type")).toHaveAttribute("data-invalid", "server");
  await expect(field("type")).toContainText("Conflicts with a CNAME");
  await expect(form.locator(".result.error")).toHaveCount(0);
});

test("Route 53 validation: health check URL and threshold", async ({ page }) => {
  await page.goto("/route53?tab=health");
  const { form, field, control } = await openSheet(page, "create-health-check");
  const host = `${unique("hc")}.example.com`;
  await control("url").fill(`${host}/health`);
  await control("url").blur();
  await expect(field("url")).toHaveAttribute("data-invalid", "format");
  await field("url").getByRole("button", { name: /Add https/ }).click();
  await expect(control("url")).toHaveValue(`https://${host}/health`);

  // The failure threshold waits under More.
  await form.locator("summary", { hasText: "More" }).click();
  await control("threshold").fill("20");
  await control("threshold").blur();
  await expect(field("threshold")).toHaveAttribute("data-invalid", "range");
  await field("threshold").getByRole("button", { name: /maximum/ }).click();
  await expect(control("threshold")).toHaveValue("10");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, host)).toBeVisible();
});

test("Route 53: routing policies, aliases with their zone, and renames that leave nothing behind", async ({ page }) => {
  const domain = `${unique("dash-rp")}.example.com`;
  await page.goto("/route53");
  await submit(page, "create-zone", { name: domain });
  await expect(page.getByRole("heading", { level: 1, name: domain })).toBeVisible();
  const zoneId = new URL(page.url()).searchParams.get("id")!;

  // Two weighted records for one name (the routing policy is folded under "Routing").
  await unfold(page, "create-record", "Routing");
  await submit(page, "create-record", { name: `api.${domain}`, type: "A", values: "192.0.2.21", policy: "weighted", setId: "blue", weight: "70" });
  await expect(row(page, "192.0.2.21")).toContainText("weight 70");
  await unfold(page, "create-record", "Routing");
  await submit(page, "create-record", { name: `api.${domain}`, type: "A", values: "192.0.2.22", policy: "weighted", setId: "green", weight: "30" });
  await expect(row(page, "192.0.2.22")).toContainText("weight 30");

  // Editing keeps the set identifier and policy (an UPSERT of that set).
  await submit(page, `edit-record-api.${domain}.-A-blue`, { weight: "50" });
  await expect(row(page, "192.0.2.21")).toContainText("weight 50");
  await expect(row(page, "192.0.2.22")).toContainText("weight 30");

  // An alias to a record of this zone gets this zone's id as its target zone.
  await page.goto(`/route53/zone?id=${zoneId}`);
  const form = page.locator("dialog[open]").getByTestId("create-record").and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId("create-record-open").first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  await form.locator('[name="name"]').fill(`www.${domain}`);
  await form.locator('[name="aliasOn"]').check();
  await form.getByLabel("Alias target").first().selectOption(`api.${domain}`);
  await expect(form.locator('[name="alias"]')).toHaveValue(`api.${domain}`);
  await expect(form.locator('[name="aliasZone"]')).toHaveValue(zoneId);
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, `www`).filter({ hasText: "Record" })).toBeVisible();

  // Renaming a record replaces it instead of adding a second one.
  await submit(page, "create-record", { name: `old.${domain}`, type: "TXT", values: '"hello"' });
  await expect(row(page, `"hello"`)).toContainText("old");
  await submit(page, `edit-record-old.${domain}.-TXT`, { name: `new.${domain}` });
  await expect(row(page, '"hello"')).toHaveCount(1);
  await expect(row(page, '"hello"')).toContainText("new");

  // The zone's own answer for the weighted name.
  const status = await submit(page, "test-record", { name: `api.${domain}`, type: "A" });
  await expect(status).toContainText("NOERROR");
});

test("Route 53: health check detail, edit and tags; zone tags and query logging", async ({ page }) => {
  const name = unique("hc-tcp");
  await page.goto("/route53?tab=health");
  // What to monitor is a tile.
  const hc = await openSheet(page, "create-health-check");
  await hc.form.getByTestId("health-kind-TCP").click();
  await submit(page, "create-health-check", { checkName: name, host: "192.0.2.80", port: "22" });
  await page.getByRole("link", { name }).click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await submit(page, "edit-health-check", { threshold: "5" });
  await expect(page.getByText("30s × 5")).toBeVisible();
  await submit(page, "add-health-tag", { key: "team", value: "edge" });
  await expect(row(page, "team")).toContainText("edge");

  const domain = `${unique("dash-ql")}.example.com`;
  await page.goto("/route53");
  await submit(page, "create-zone", { name: domain });
  await expect(page.getByRole("heading", { level: 1, name: domain })).toBeVisible();
  await page.getByRole("link", { name: "Tags" }).click();
  await submit(page, "add-zone-tag", { key: "env", value: "test" });
  await expect(row(page, "env")).toContainText("test");
  await page.getByRole("link", { name: "Query logging" }).click();
  // Its own log group, made with Route 53's resource policy.
  const logging = await openSheet(page, "create-query-logging");
  await logging.form.getByRole("button", { name: "Create automatically" }).click();
  await logging.form.locator('button[type="submit"]').click();
  await expect(row(page, `/aws/route53/${domain}`)).toBeVisible();
  await page.getByRole("link", { name: "DNSSEC signing" }).click();
  const ksk = await openSheet(page, "create-ksk");
  await ksk.form.getByRole("button", { name: "Create automatically" }).click();
  await ksk.form.locator('button[type="submit"]').click();
  await expect(row(page, "_ksk")).toContainText("active");
  await page.getByTestId("enable-dnssec").locator("button").click();
  await expect(page.getByText(/DS record for the parent zone/)).toBeVisible();
});

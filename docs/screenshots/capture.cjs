// Capture the README screenshots from a running console (dashboard/, port
// 3000) and MWS seeded by seed.py:
//
//   cd dashboard && node ../docs/screenshots/capture.cjs   # writes docs/screenshots/*.png
//
// Then convert them to the README's WebP files with
// `python docs/screenshots/shrink.py`.
const { chromium } = require("playwright");
const path = require("path");

const BASE = process.env.MWS_DASHBOARD_URL ?? "http://127.0.0.1:3000";
const OUT = __dirname;
const ACCOUNT = "123456789012";

const enc = encodeURIComponent;

/** name, URL, and an optional step run before the screenshot. */
const SHOTS = [
  ["home", "/"],
  ["search", "/", async (page) => {
    await page.locator("body").press("/");
    await page.keyboard.type("orders", { delay: 60 });
    await page.waitForTimeout(2500);
  }],
  ["iam-policy", `/iam/policy?arn=${enc(`arn:aws:iam::${ACCOUNT}:policy/OrdersReadWrite`)}`],
  ["iam-simulator", `/iam/simulator?principal=${enc(`arn:aws:iam::${ACCOUNT}:role/orders-processor`)}&actions=${enc("sqs:SendMessage, sqs:PurgeQueue, s3:PutObject, s3:DeleteBucket")}&resources=${enc(`arn:aws:sqs:us-east-1:${ACCOUNT}:orders, arn:aws:s3:::storefront-receipts/2026/order-1.json`)}`],
  ["lambda-test", "/lambda/process-order?tab=test", async (page) => {
    const payload = page.locator('textarea[name="payload"]');
    await payload.fill(JSON.stringify({ orderId: 1042, items: [{ sku: "SKU-0007", price: 19.99, qty: 2 }, { sku: "SKU-0012", price: 4.5, qty: 1 }] }, null, 2));
    await page.getByRole("button", { name: "Invoke" }).click();
    await page.waitForTimeout(3000);
  }],
  ["s3-bucket", "/s3/storefront-assets"],
  ["sqs-queue", "/sqs/orders"],
  ["metrics", `/metrics?ns=Storefront&metric=CheckoutLatency&dims=${enc(JSON.stringify([{ Name: "Stage", Value: "prod" }]))}`],
  ["alarms", "/alarms"],
  ["logs", `/logs/group?name=${enc("/storefront/web")}`],
  ["kms-key", "/kms/key?id=alias/storefront"],
  ["vpc-map", "/vpc", async (page) => {
    await page.locator('a[href^="/vpc/vpc-"]').first().click();
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(2000);
  }],
  ["ec2", "/ec2"],
  ["route53", "/route53", async (page) => {
    await page.getByRole("link", { name: "storefront.example" }).click();
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(1500);
  }],
  ["pca", "/pca", async (page) => {
    await page.getByRole("link", { name: "Storefront Root CA" }).click();
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(1500);
  }],
  ["cloudformation", "/cloudformation/stack?name=storefront-images"],
  ["organizations", "/organizations"],
  ["bedrock", "/bedrock"],
  ["create-form", "/sqs", async (page) => {
    const opener = page.getByTestId("create-queue-open").first();
    await opener.click();
    const form = page.locator("dialog[open]").getByTestId("create-queue").and(page.locator("form"));
    await form.locator('[name="name"]').fill("orders queue!");
    await form.locator('[name="name"]').blur();
    await page.waitForTimeout(1200);
  }],
  ["control", "/control"],
  ["home-dark", "/", null, { colorScheme: "dark" }],
];

(async () => {
  const only = process.argv.slice(2);
  const browser = await chromium.launch();
  for (const [name, url, step, extra] of SHOTS) {
    if (only.length && !only.includes(name)) continue;
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, ...(extra ?? {}) });
    const page = await context.newPage();
    try {
      await page.goto(BASE + url, { waitUntil: "networkidle", timeout: 90_000 });
      await page.waitForTimeout(1500);
      if (step) await step(page);
      await page.screenshot({ path: path.join(OUT, `${name}.png`) });
      console.log("ok", name);
    } catch (err) {
      console.log("FAILED", name, err.message.split("\n")[0]);
    }
    await context.close();
  }
  await browser.close();
})();

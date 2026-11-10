import { expect, test, type Page } from "@playwright/test";

import { AllocateAddressCommand, EC2Client, ReleaseAddressCommand } from "@aws-sdk/client-ec2";

import { row, sdk, submit, unique } from "./helpers";

test("Global Accelerator: create an accelerator with a listener", async ({ page }) => {
  const name = unique("dash-ga");
  await page.goto("/ga");
  await submit(page, "create-accelerator", { name });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await submit(page, "add-ga-listener", { ports: "443" });
  await expect(page.getByRole("heading", { name: "TCP 443" })).toBeVisible();
});

async function openSheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field, control: (name: string) => form.locator(`[name="${name}"]`) };
}

test("Global Accelerator: fields repair names, ports in use and unknown endpoints", async ({ page }) => {
  await page.goto("/ga");
  const create = await openSheet(page, "create-accelerator");
  // Spaces and punctuation are not allowed in a name: one click cleans it.
  const typed = `${unique("Dash Edge")}!`;
  await create.control("name").fill(typed);
  await create.control("name").blur();
  await expect(create.field("name")).toHaveAttribute("data-invalid", "pattern");
  await create.field("name").getByRole("button", { name: /Remove unsupported/ }).click();
  const name = typed.replace(/\s+/g, "-").replace(/!$/, "");
  await expect(create.control("name")).toHaveValue(name);
  await create.form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();

  await submit(page, "add-ga-listener", { ports: "443" });
  await expect(page.getByRole("heading", { name: "TCP 443" })).toBeVisible();

  // The ports field knows what the accelerator's TCP listeners already use.
  const listener = await openSheet(page, "add-ga-listener");
  const ports = listener.field("ports");
  await expect(listener.control("ports")).toHaveValue("80");
  await listener.control("ports").fill("443");
  await listener.control("ports").blur();
  await expect(ports).toHaveAttribute("data-invalid", "format");
  await expect(ports.locator(".field-issue")).toContainText("443 is already in use");
  // UDP 443 is free...
  await listener.control("protocol").selectOption("UDP");
  await expect(ports).not.toHaveAttribute("data-invalid");
  // ...and on TCP the field offers the next free port.
  await listener.control("protocol").selectOption("TCP");
  await expect(ports).toHaveAttribute("data-invalid", "format");
  await ports.getByRole("button", { name: /Use 8443/ }).click();
  await expect(listener.control("ports")).toHaveValue("8443");
  // Typed range separators are tidied.
  await listener.control("ports").fill("9010:9000");
  await listener.control("ports").blur();
  await ports.getByRole("button", { name: /Tidy/ }).click();
  await expect(listener.control("ports")).toHaveValue("9000-9010");
  await listener.form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { name: "TCP 9000-9010" })).toBeVisible();

  // An endpoint MWS does not know comes back onto the endpoint field.
  const group = await openSheet(page, "add-endpoint-group-0");
  await group.control("endpoint").fill("i-0123456789abcdef0");
  await group.form.locator('button[type="submit"]').click();
  await expect(group.field("endpoint")).toHaveAttribute("data-invalid", "server");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  // A bare name is not an endpoint: the field says what it takes.
  await group.control("endpoint").fill("my load balancer");
  await group.control("endpoint").blur();
  await expect(group.field("endpoint")).toHaveAttribute("data-invalid", "pattern");
  await expect(group.field("endpoint").locator(".field-issue")).toContainText("load balancer ARN");
});

test("Global Accelerator: endpoint groups with several weighted endpoints, traffic dial and edits", async ({ page }) => {
  test.setTimeout(240_000);
  // Elastic IPs in a Region of their own (us-east-1's quota is shared with
  // other specs), released at the end.
  const region = "us-west-2";
  const ec2 = new EC2Client({ ...sdk, region });
  const [a, b] = await Promise.all([ec2.send(new AllocateAddressCommand({ Domain: "vpc" })), ec2.send(new AllocateAddressCommand({ Domain: "vpc" }))]);
  try {
    const name = unique("dash-ga-eg");
    await page.goto("/ga");
    await submit(page, "create-accelerator", { name });
    await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
    await submit(page, "add-ga-listener", { ports: "443" });
    await expect(page.getByRole("heading", { name: "TCP 443" })).toBeVisible();
    // The listener takes client affinity.
    await submit(page, "edit-ga-listener-0", { ports: "443, 8443", affinity: "SOURCE_IP" });
    await expect(page.getByRole("heading", { name: "TCP 443, 8443" })).toBeVisible();

    // A group in another Region, with one weighted endpoint from there.
    await submit(page, "add-endpoint-group-0", { region, endpoint: `${a.AllocationId}=200`, dial: "60" });
    await expect(row(page, region)).toContainText("60%");
    await row(page, region).getByRole("link").click();
    await expect(page.getByRole("heading", { level: 1, name: region })).toBeVisible();
    await expect(row(page, a.AllocationId!)).toContainText("200");

    // Another endpoint, then new weights and dial for the group.
    await submit(page, "add-endpoints", { endpoint: `${b.AllocationId}=50` });
    await expect(row(page, b.AllocationId!)).toContainText("50");
    await submit(page, "edit-endpoint-group", { dial: "25", [`weight:${a.AllocationId}`]: "10", overrides: "443=8443" });
    await expect(page.getByText("25%").first()).toBeVisible();
    await expect(page.getByText("443→8443")).toBeVisible();
    await expect(row(page, a.AllocationId!)).toContainText("10");

    // Removing an endpoint leaves the other.
    page.once("dialog", (d) => d.accept().catch(() => {}));
    await row(page, b.AllocationId!).getByRole("button", { name: /^Remove/ }).click();
    await expect(row(page, b.AllocationId!)).toHaveCount(0);
    await expect(row(page, a.AllocationId!)).toBeVisible();
  } finally {
    await Promise.all([a, b].map((x) => ec2.send(new ReleaseAddressCommand({ AllocationId: x.AllocationId })).catch(() => {})));
  }
});

import { test } from "@playwright/test";

import { submit } from "./helpers";

test("EventBridge: put an event on the default bus", async ({ page }) => {
  await page.goto("/events");
  await submit(page, "put-event", { detail: '{"from": "playwright"}' });
});

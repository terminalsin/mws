import { CreateDBInstanceCommand, DescribeDBClustersCommand, DescribeDBInstancesCommand, RDSClient } from "@aws-sdk/client-rds";
import { expect, test, type Page } from "@playwright/test";

import { row, sdk, submit, unique } from "./helpers";

test("RDS: create a PostgreSQL database and find its connection command", async ({ page }) => {
  const id = unique("dash-db");
  await page.goto("/rds");
  await submit(page, "create-database", { engine: "postgres", id, username: "app", password: "correct-horse-battery" });
  await expect(page.getByRole("heading", { level: 1, name: id })).toBeVisible();
  await expect(page.locator(".specs")).toContainText("postgres");

  // A snapshot name already used on this database is flagged in place,
  // with the next free name one click away.
  const snap = `${id}-before-upgrade`;
  await submit(page, "take-snapshot", { name: snap });
  const sheet = await openSheet(page, "take-snapshot");
  const field = sheet.field("name");
  await field.locator("input").fill(snap);
  await field.locator("input").blur();
  await expect(field).toHaveAttribute("data-invalid", "taken");
  await field.getByRole("button", { name: /Use / }).click();
  await expect(field.locator("input")).toHaveValue(`${snap}-2`);
  await expect(field).not.toHaveAttribute("data-invalid");
  await sheet.form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);

  await page.goto("/rds");
  await expect(row(page, id)).toBeVisible();
});

test("RDS: create-database fields repair what RDS would reject", async ({ page }) => {
  await page.goto("/rds");
  const { form, field } = await openSheet(page, "create-database");

  // RDS identifiers: lower case, single hyphens.
  const id = field("id");
  await id.locator("input").fill("Orders DB");
  await id.locator("input").blur();
  await expect(id).toHaveAttribute("data-invalid", "pattern");
  await id.getByRole("button", { name: /Lowercase/ }).click();
  await expect(id.locator("input")).toHaveValue("orders-db");
  await expect(id).not.toHaveAttribute("data-invalid");

  // Passwords: printable ASCII without / @ " or spaces, or a generated one.
  const password = field("password");
  await password.locator("input").fill("p@ss word");
  await password.locator("input").blur();
  await expect(password).toHaveAttribute("data-invalid", "pattern");
  await expect(password.getByRole("button", { name: /Remove unsupported/ })).toBeVisible();
  await password.locator("input").fill("");
  await form.locator('button[type="submit"]').click();
  await expect(password).toHaveAttribute("data-invalid", "required");
  await password.getByRole("button", { name: /Generate/ }).click();
  await expect(password.locator("input")).not.toHaveValue("");
  await expect(password).not.toHaveAttribute("data-invalid");

  // Aurora has no micro instances: the untouched default follows the
  // engine, and a typed one is answered with the sizes Aurora offers.
  const cls = field("class");
  await form.locator('select[name="engine"]').selectOption("aurora-postgresql");
  await expect(cls.locator("input")).toHaveValue("db.t4g.medium");
  await expect(form.locator('input[name="storage"]')).toHaveCount(0);
  await cls.locator("input").fill("db.t4g.micro");
  await cls.locator("input").blur();
  await expect(cls).toHaveAttribute("data-invalid", "enum");
  await cls.getByRole("button", { name: /db\.t4g\.medium/ }).click();
  await expect(cls).not.toHaveAttribute("data-invalid");

  // MySQL user names stop at 32 characters.
  await form.locator('select[name="engine"]').selectOption("mysql");
  const user = field("username");
  await expect(user.locator("input")).toHaveValue("admin");
  await user.locator("input").fill("a".repeat(40));
  await user.locator("input").blur();
  await expect(user).toHaveAttribute("data-invalid", "tooLong");
  await user.getByRole("button", { name: /Shorten to 32/ }).click();
  await expect(user).not.toHaveAttribute("data-invalid");
});

test("RDS: an Aurora cluster lists its instances, and deleting it deletes them first", async ({ page }) => {
  test.setTimeout(240_000);
  const id = unique("dash-aurora");
  await page.goto("/rds");
  await submit(page, "create-database", { engine: "aurora-postgresql", id, username: "app", password: "correct-horse-battery" });
  await expect(page.getByRole("heading", { level: 1, name: id })).toBeVisible();
  const instances = page.getByLabel("Instances", { exact: true });
  await expect(instances.locator("li.row").filter({ hasText: `${id}-instance-1` })).toContainText("Writer");

  // A reader joins the cluster from its page.
  await submit(page, "add-instance", { id: `${id}-reader` });
  await expect(instances.locator("li.row").filter({ hasText: `${id}-reader` })).toBeVisible();

  // Each member has its own page, which leads back to the cluster.
  await instances.locator("li.row").filter({ hasText: `${id}-reader` }).locator("a").click();
  await expect(page.getByRole("heading", { level: 1, name: `${id}-reader` })).toBeVisible();
  await expect(page.locator(".specs")).toContainText("Reader");
  await page.getByRole("link", { name: id, exact: true }).first().click();
  await expect(page.getByRole("heading", { level: 1, name: id })).toBeVisible();

  // RDS refuses to delete a cluster with instances; the console deletes them first.
  await submit(page, "delete-database");
  await expect(page).toHaveURL(/\/rds$/);
  const client = new RDSClient(sdk);
  await expect(client.send(new DescribeDBClustersCommand({ DBClusterIdentifier: id }))).rejects.toThrow(/not found/i);
  await expect(client.send(new DescribeDBInstancesCommand({ DBInstanceIdentifier: `${id}-reader` }))).rejects.toThrow(/not found/i);
});

test("RDS: modify an instance, then restore it from a snapshot and to a point in time", async ({ page }) => {
  test.setTimeout(180_000);
  const id = unique("dash-pg");
  const client = new RDSClient(sdk);
  await client.send(
    new CreateDBInstanceCommand({ DBInstanceIdentifier: id, Engine: "postgres", DBInstanceClass: "db.t4g.micro", MasterUsername: "app", MasterUserPassword: "correct-horse-1", AllocatedStorage: 20, BackupRetentionPeriod: 1 }),
  );
  await page.goto(`/rds/db?id=${id}`);
  await expect(page.locator(".specs")).toContainText("db.t4g.micro");

  // Relationships: the network it lives in and its parameter group.
  await expect(page.locator("main")).toContainText("Publicly accessible");
  await page.getByRole("link", { name: "Configuration" }).click();
  await expect(page.locator("main")).toContainText("Parameter group");

  // Modify: a bigger class, applied now.
  await submit(page, "modify-database", { class: "db.t4g.small", retention: "3" });
  await expect(page.locator(".specs")).toContainText("db.t4g.small");
  await page.getByRole("link", { name: "Maintenance & backups" }).click();
  await expect(page.locator("main")).toContainText("3 days");

  // A snapshot, restored into a new database.
  const snap = `${id}-snap`;
  await submit(page, "take-snapshot", { name: snap });
  await page.goto("/rds?tab=snapshots");
  await expect(row(page, snap)).toContainText("available");
  await submit(page, `restore-${snap}`, { id: `${id}-restored` });
  await expect(page.getByRole("heading", { level: 1, name: `${id}-restored` })).toBeVisible();

  // Point in time: the latest restorable time.
  await page.goto(`/rds/db?id=${id}`);
  await submit(page, "restore-pitr", { id: `${id}-pitr` });
  await expect(page.getByRole("heading", { level: 1, name: `${id}-pitr` })).toBeVisible();
  const restored = (await client.send(new DescribeDBInstancesCommand({ DBInstanceIdentifier: `${id}-pitr` }))).DBInstances![0];
  expect(restored.Engine).toBe("postgres");
});

async function openSheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field };
}

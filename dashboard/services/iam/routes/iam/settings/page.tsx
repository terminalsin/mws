import { GetAccountPasswordPolicyCommand, GetAccountSummaryCommand, ListAccountAliasesCommand } from "@aws-sdk/client-iam";
import { frameInfo, load } from "@mws-dashboard/aws";
import { ActionForm, ErrorNotice, Facts, Field, List, Metric, Metrics, Page, Section, Sheet } from "@mws-dashboard/ui";
import { CreateAccountAlias, UpdateAccountPasswordPolicy } from "@mws-dashboard/ui/model/iam";
import { AtSign, KeyRound, Pencil, RotateCcw, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { iam } from "../../../lib/clients";
import { createAccountAlias, deleteAccountAlias, deletePasswordPolicy, savePasswordPolicy } from "../actions";

export const metadata: Metadata = { title: "Account settings" };

/** The account's IAM settings: its sign-in alias, password policy and how
 * close it is to IAM's quotas. */
export default async function Settings() {
  const [data, info] = await Promise.all([
    load(async () => {
      const client = await iam();
      const [aliases, policy, summary] = await Promise.all([
        client.send(new ListAccountAliasesCommand({})).then((r) => r.AccountAliases ?? []),
        client.send(new GetAccountPasswordPolicyCommand({})).then(
          (r) => r.PasswordPolicy ?? null,
          (e) => {
            if ((e as { name?: string }).name === "NoSuchEntityException") return null;
            throw e;
          },
        ),
        client.send(new GetAccountSummaryCommand({})).then((r) => r.SummaryMap ?? {}),
      ]);
      return { aliases, policy, summary };
    }),
    frameInfo(),
  ]);
  if (!data.ok) {
    return (
      <Page title="Account settings" back={{ href: "/iam", label: "IAM" }}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { aliases, policy, summary } = data.value;
  const usage = (used: keyof typeof summary, quota: keyof typeof summary, label: string) => {
    const n = summary[used] ?? 0;
    const max = summary[quota];
    return <Metric key={used} label={label} value={max ? `${n} / ${max}` : n} tone={max && n / max > 0.8 ? "warn" : undefined} />;
  };
  const rules = UpdateAccountPasswordPolicy;
  return (
    <Page title="Account settings" back={{ href: "/iam", label: "IAM" }} subtitle={info.account ?? undefined}>
      <Metrics>
        {usage("Users", "UsersQuota", "Users")}
        {usage("Roles", "RolesQuota", "Roles")}
        {usage("Groups", "GroupsQuota", "Groups")}
        {usage("Policies", "PoliciesQuota", "Customer managed policies")}
        {summary.AccountMFAEnabled === 0 && <Metric label="Root MFA" value="off" tone="bad" />}
      </Metrics>

      <Section
        title="Account alias"
        plain
        actions={
          aliases.length === 0 && (
            <Sheet title="Create account alias" label="Create account alias" icon={<AtSign size={16} />} testId="create-alias">
              <ActionForm action={createAccountAlias} submit="Create" testId="create-alias">
                <Field label="Alias" rule={CreateAccountAlias.AccountAlias} unique>
                  <input name="alias" required />
                </Field>
              </ActionForm>
            </Sheet>
          )
        }
      >
        <List
          label="Account alias"
          rows={aliases.map((a) => ({
            key: a,
            icon: <AtSign size={18} />,
            title: a,
            subtitle: `https://${a}.signin.aws.amazon.com/console`,
            actions: <ActionForm action={deleteAccountAlias.bind(null, a)} submit={`Delete ${a}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete the alias ${a}?`} />,
          }))}
        />
      </Section>

      <Section
        title="Password policy"
        icon={<KeyRound size={16} />}
        actions={
          <>
            <Sheet title="Password policy" label="Edit password policy" icon={<Pencil size={16} />} testId="password-policy">
              <ActionForm action={savePasswordPolicy} submit="Save" testId="password-policy">
                <Field label="Minimum length" rule={rules.MinimumPasswordLength}>
                  <input name="length" type="number" defaultValue={policy?.MinimumPasswordLength ?? 8} />
                </Field>
                <fieldset className="checks">
                  <legend>Require</legend>
                  <label className="check">
                    <input type="checkbox" name="upper" defaultChecked={policy?.RequireUppercaseCharacters} /> Uppercase letter
                  </label>
                  <label className="check">
                    <input type="checkbox" name="lower" defaultChecked={policy?.RequireLowercaseCharacters} /> Lowercase letter
                  </label>
                  <label className="check">
                    <input type="checkbox" name="numbers" defaultChecked={policy?.RequireNumbers} /> Number
                  </label>
                  <label className="check">
                    <input type="checkbox" name="symbols" defaultChecked={policy?.RequireSymbols} /> Symbol
                  </label>
                </fieldset>
                <label className="check">
                  <input type="checkbox" name="change" defaultChecked={policy?.AllowUsersToChangePassword ?? true} /> Users can change their own password
                </label>
                <Field label="Expire after (days)" rule={rules.MaxPasswordAge}>
                  <input name="age" type="number" defaultValue={policy?.MaxPasswordAge} />
                </Field>
                <label className="check">
                  <input type="checkbox" name="expiry" defaultChecked={policy?.HardExpiry} /> Expired passwords need an administrator reset
                </label>
                <Field label="Prevent reuse of the last" rule={rules.PasswordReusePrevention}>
                  <input name="reuse" type="number" defaultValue={policy?.PasswordReusePrevention} />
                </Field>
              </ActionForm>
            </Sheet>
            {policy && <ActionForm action={deletePasswordPolicy} submit="Reset to AWS default" icon={<RotateCcw size={16} />} confirm="Use AWS's default password policy?" testId="delete-password-policy" />}
          </>
        }
      >
        {policy ? (
          <Facts
            items={[
              ["Minimum length", policy.MinimumPasswordLength],
              [
                "Requires",
                [policy.RequireUppercaseCharacters && "uppercase", policy.RequireLowercaseCharacters && "lowercase", policy.RequireNumbers && "number", policy.RequireSymbols && "symbol"].filter(Boolean).join(", ") || "—",
              ],
              policy.ExpirePasswords && ["Expires after", `${policy.MaxPasswordAge} days${policy.HardExpiry ? ", admin reset" : ""}`],
              policy.PasswordReusePrevention && ["Remembers", `${policy.PasswordReusePrevention} passwords`],
              ["Users change their own", policy.AllowUsersToChangePassword ? "yes" : "no"],
            ]}
          />
        ) : (
          <Facts items={[["Policy", "AWS default: 8 characters, three of four character types"]]} />
        )}
      </Section>
    </Page>
  );
}

import type { Rule } from "@mws-dashboard/ui";

// RDS's model leaves these members unconstrained; the rules are in its
// docs (and what MWS enforces, as RDS does). RDS stores identifiers in
// lower case, so the console asks for them that way.

/** Instances and clusters (63) and snapshots (255). */
export function identifier(maxLength: number): Rule {
  return {
    required: true,
    maxLength,
    pattern: "^(?!.*--)(?!.*-$)[a-z][a-z0-9-]*$",
    hint: "a–z, 0–9 and single hyphens, starting with a letter",
    generate: "name",
  };
}

/** The engines the console creates. */
export const ENGINES = [
  { value: "postgres", label: "PostgreSQL" },
  { value: "mysql", label: "MySQL" },
  { value: "mariadb", label: "MariaDB" },
  { value: "aurora-postgresql", label: "Aurora PostgreSQL" },
  { value: "aurora-mysql", label: "Aurora MySQL" },
];

export type Family = "postgres" | "mysql";

export const family = (engine: string): Family => (engine.includes("postgres") ? "postgres" : "mysql");

export function username(f: Family): Rule {
  return {
    required: true,
    maxLength: f === "postgres" ? 63 : 32,
    pattern: "^[A-Za-z][A-Za-z0-9_]*$",
    hint: "Letters, digits and _, starting with a letter",
  };
}

export function password(f: Family): Rule {
  return {
    required: true,
    minLength: 8,
    maxLength: f === "postgres" ? 128 : 41,
    pattern: '^[!#-.0-?A-~]+$',
    hint: 'Printable ASCII except /, @, " and spaces',
    generate: "password",
  };
}

/** gp3 storage, in GiB. */
export const STORAGE: Rule = { type: "integer", min: 20, max: 65536 };

/** Automated backups: 0 turns them (and point-in-time restore) off. */
export const RETENTION: Rule = { type: "integer", min: 0, max: 35 };

/** The database RDS creates at launch: letters, digits and _. */
export const DATABASE_NAME: Record<Family, Rule> = {
  postgres: { maxLength: 63, pattern: "^[A-Za-z][A-Za-z0-9_]*$", hint: "Letters, digits and _, starting with a letter" },
  mysql: { maxLength: 64, pattern: "^[A-Za-z][A-Za-z0-9_]*$", hint: "Letters, digits and _, starting with a letter" },
};

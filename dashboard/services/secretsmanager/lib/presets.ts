// What a new secret usually holds. Picking one fills a name and a value in
// the shape its clients read (database secrets follow the JSON structure
// RDS and its rotation functions use). Shared by the server pages and the
// client fields (no server-only imports).

export interface SecretPreset {
  id: string;
  label: string;
  icon: string;
  group: string;
  /** The suggested name, made unique against the existing ones. */
  name: string;
  /** The value, with `{password}` where a generated one goes. */
  value?: Record<string, string | number>;
  /** Secret names that hold this kind, for a list row's logo. */
  match?: RegExp;
}

const db = (engine: string, port: number, extra: Record<string, string> = { dbname: "app" }) => ({
  engine,
  host: "localhost",
  port,
  username: "app",
  password: "{password}",
  ...extra,
});

export const SECRET_PRESETS: SecretPreset[] = [
  { id: "postgres", label: "PostgreSQL", icon: "brand/postgresql", group: "Database", name: "app/postgres", value: db("postgres", 5432), match: /postgres|pg\b|psql/i },
  { id: "mysql", label: "MySQL", icon: "brand/mysql", group: "Database", name: "app/mysql", value: db("mysql", 3306), match: /mysql/i },
  { id: "mariadb", label: "MariaDB", icon: "brand/mariadb", group: "Database", name: "app/mariadb", value: db("mariadb", 3306), match: /maria/i },
  { id: "redis", label: "Redis", icon: "brand/redis", group: "Database", name: "app/redis", value: { host: "localhost", port: 6379, password: "{password}" }, match: /redis|valkey|elasticache/i },
  { id: "mongodb", label: "MongoDB", icon: "brand/mongodb", group: "Database", name: "app/mongodb", value: db("mongo", 27017), match: /mongo|docdb|documentdb/i },
  { id: "api-key", label: "API key", icon: "", group: "Other", name: "app/api-key", value: { api_key: "{password}" }, match: /api.?key|token/i },
  { id: "credentials", label: "User and password", icon: "resource/AWSIdentityAccessManagementLongTermSecurityCredential", group: "Other", name: "app/credentials", value: { username: "app", password: "{password}" } },
  { id: "plaintext", label: "Plain text", icon: "", group: "Other", name: "app/secret" },
];

/** A secret's logo from its name: its database's, else none. */
export function secretLogo(name: string): string | undefined {
  return SECRET_PRESETS.find((p) => p.match && p.icon.startsWith("brand/") && p.match.test(name))?.icon;
}

/** A preset's value with `password` in place, pretty-printed. */
export function presetValue(p: SecretPreset, password: string): string {
  if (!p.value) return "";
  const v = Object.fromEntries(Object.entries(p.value).map(([k, x]) => [k, x === "{password}" ? password : x]));
  return JSON.stringify(v, null, 2);
}

// The engines the create sheet opens on, as logo tiles. Plain data, so both
// the server page and the client form can import it.

export interface EnginePreset {
  id: string;
  label: string;
  icon: string;
  group: string;
}

export const ENGINE_PRESETS: EnginePreset[] = [
  { id: "postgres", label: "PostgreSQL", icon: "brand/postgresql", group: "RDS" },
  { id: "mysql", label: "MySQL", icon: "brand/mysql", group: "RDS" },
  { id: "mariadb", label: "MariaDB", icon: "brand/mariadb", group: "RDS" },
  { id: "aurora-postgresql", label: "Aurora PostgreSQL", icon: "resource/AmazonAuroraPostgreSQLInstance", group: "Aurora" },
  { id: "aurora-mysql", label: "Aurora MySQL", icon: "resource/AmazonAuroraMySQLInstance", group: "Aurora" },
];

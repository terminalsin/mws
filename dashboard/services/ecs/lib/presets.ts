// Starting points for a new task definition: a well-known image with the
// port, size and settings it needs. Plain data, shared by server and client.

export interface ImagePreset {
  id: string;
  label: string;
  icon: string;
  group?: string;
  image: string;
  port?: string;
  cpu: string;
  memory: string;
  command?: string;
  env?: string;
}

const LIB = "public.ecr.aws/docker/library";

export const IMAGE_PRESETS: ImagePreset[] = [
  { id: "nginx", label: "nginx", icon: "brand/nginx", group: "Web", image: "public.ecr.aws/nginx/nginx:latest", port: "80", cpu: "256", memory: "512" },
  { id: "httpd", label: "Apache", icon: "brand/apache", group: "Web", image: `${LIB}/httpd:2.4`, port: "80", cpu: "256", memory: "512" },
  { id: "node", label: "Node.js", icon: "brand/nodedotjs", group: "Web", image: `${LIB}/node:22-alpine`, port: "3000", cpu: "512", memory: "1024" },
  { id: "python", label: "Python", icon: "brand/python", group: "Web", image: `${LIB}/python:3.13-slim`, port: "8000", cpu: "256", memory: "512", command: "python -m http.server 8000" },
  { id: "grafana", label: "Grafana", icon: "brand/grafana", group: "Web", image: "grafana/grafana:latest", port: "3000", cpu: "512", memory: "1024" },
  { id: "postgres", label: "PostgreSQL", icon: "brand/postgresql", group: "Data", image: `${LIB}/postgres:17`, port: "5432", cpu: "512", memory: "1024", env: "POSTGRES_PASSWORD=postgres" },
  { id: "mysql", label: "MySQL", icon: "brand/mysql", group: "Data", image: `${LIB}/mysql:8.4`, port: "3306", cpu: "512", memory: "1024", env: "MYSQL_ROOT_PASSWORD=mysql" },
  { id: "redis", label: "Redis", icon: "brand/redis", group: "Data", image: `${LIB}/redis:7`, port: "6379", cpu: "256", memory: "512" },
  { id: "mongo", label: "MongoDB", icon: "brand/mongodb", group: "Data", image: `${LIB}/mongo:8`, port: "27017", cpu: "512", memory: "1024" },
  { id: "rabbitmq", label: "RabbitMQ", icon: "brand/rabbitmq", group: "Data", image: `${LIB}/rabbitmq:4`, port: "5672", cpu: "512", memory: "1024" },
  { id: "alpine", label: "Alpine", icon: "brand/alpinelinux", group: "Other", image: `${LIB}/alpine:3`, cpu: "256", memory: "512", command: "sleep 3600" },
  { id: "custom", label: "Custom", icon: "brand/docker", group: "Other", image: "", cpu: "256", memory: "512" },
];

/** The logo of a well-known image ("…/library/postgres:17" → PostgreSQL), else undefined. */
export function imageIcon(image: string | undefined): string | undefined {
  const repo = (image ?? "").split("@")[0].split("/").pop()?.split(":")[0] ?? "";
  const hit = IMAGE_PRESETS.find((p) => p.id !== "custom" && p.image && p.image.split("/").pop()!.split(":")[0] === repo);
  return hit?.icon;
}

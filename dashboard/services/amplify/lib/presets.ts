// What the create-app sheet fills in: where the code comes from and the
// framework that builds it. Shared by the server page and the client fields
// (no server-only imports).

export interface Source {
  id: string;
  label: string;
  /** An icon id; the upload tile draws its own. */
  icon: string;
  /** Placeholder for the repository URL. */
  repo?: string;
  /** Where to make an access token. */
  tokenUrl?: string;
}

export const SOURCES: Source[] = [
  { id: "manual", label: "Upload", icon: "" },
  { id: "github", label: "GitHub", icon: "brand/github", repo: "https://github.com/org/site", tokenUrl: "https://github.com/settings/tokens" },
  { id: "gitlab", label: "GitLab", icon: "brand/gitlab", repo: "https://gitlab.com/org/site", tokenUrl: "https://gitlab.com/-/user_settings/personal_access_tokens" },
  { id: "bitbucket", label: "Bitbucket", icon: "brand/bitbucket", repo: "https://bitbucket.org/org/site", tokenUrl: "https://bitbucket.org/account/settings/app-passwords/" },
  { id: "codecommit", label: "CodeCommit", icon: "service/AWSCodeCommit", repo: "https://git-codecommit.us-east-1.amazonaws.com/v1/repos/site" },
];

export type Platform = "WEB" | "WEB_COMPUTE";

export interface Framework {
  id: string;
  label: string;
  icon: string;
  /** Amplify's branch framework name. */
  framework: string;
  platform: Platform;
  /** Built output; no build spec when undefined (the repository's amplify.yml decides). */
  out?: string;
  build?: string;
}

export const FRAMEWORKS: Framework[] = [
  { id: "static", label: "Static", icon: "brand/html5", framework: "Web", platform: "WEB" },
  { id: "react", label: "React", icon: "brand/react", framework: "React", platform: "WEB", out: "dist" },
  { id: "nextjs", label: "Next.js", icon: "brand/nextdotjs", framework: "Next.js - SSR", platform: "WEB_COMPUTE", out: ".next" },
  { id: "vue", label: "Vue", icon: "brand/vuedotjs", framework: "Vue", platform: "WEB", out: "dist" },
  { id: "nuxt", label: "Nuxt", icon: "brand/nuxt", framework: "Nuxt", platform: "WEB_COMPUTE", out: ".amplify-hosting" },
  { id: "angular", label: "Angular", icon: "brand/angular", framework: "Angular", platform: "WEB", out: "dist/browser" },
  { id: "astro", label: "Astro", icon: "brand/astro", framework: "Astro", platform: "WEB", out: "dist" },
  { id: "sveltekit", label: "SvelteKit", icon: "brand/svelte", framework: "SvelteKit", platform: "WEB", out: "build" },
  { id: "gatsby", label: "Gatsby", icon: "brand/gatsby", framework: "Gatsby", platform: "WEB", out: "public" },
  { id: "hugo", label: "Hugo", icon: "brand/hugo", framework: "Hugo", platform: "WEB", out: "public", build: "hugo" },
];

/** An amplify.yml for a framework: install, build, publish its output. */
export function buildSpec(f: Framework): string | undefined {
  if (!f.out) return undefined;
  const npm = !f.build;
  const lines = ["version: 1", "frontend:", "  phases:"];
  if (npm) lines.push("    preBuild:", "      commands:", "        - npm ci");
  lines.push("    build:", "      commands:", `        - ${f.build ?? "npm run build"}`);
  lines.push("  artifacts:", `    baseDirectory: ${f.out}`, "    files:", "      - '**/*'");
  if (npm) lines.push("  cache:", "    paths:", "      - node_modules/**/*");
  return lines.join("\n");
}

/** The logo of a repository's host, for list rows. */
export function sourceIcon(repository: string | undefined): string | undefined {
  if (!repository) return undefined;
  if (/github\.com/i.test(repository)) return "brand/github";
  if (/gitlab/i.test(repository)) return "brand/gitlab";
  if (/bitbucket/i.test(repository)) return "brand/bitbucket";
  if (/codecommit/i.test(repository)) return "service/AWSCodeCommit";
  return undefined;
}

/** The logo of a branch's framework (Amplify's own names, loosely). */
export function frameworkIcon(framework: string | undefined): string | undefined {
  const f = (framework ?? "").toLowerCase();
  if (!f) return undefined;
  return FRAMEWORKS.find((x) => x.id !== "static" && (f.startsWith(x.framework.toLowerCase().split(" ")[0]) || f.includes(x.id)))?.icon;
}

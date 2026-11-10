// The upstream registries a pull through cache rule can mirror, as logo
// tiles. Picking one fills the prefix and URL; those that need a login say
// so. Plain data, so both the server page and the client form can import it.

export interface UpstreamPreset {
  id: string;
  label: string;
  icon: string;
  url: string;
  prefix: string;
  /** Needs a Secrets Manager secret (ecr-pullthroughcache/...). */
  login?: boolean;
  /** The URL names the person's own registry: they edit it. */
  own?: boolean;
}

export const UPSTREAM_PRESETS: UpstreamPreset[] = [
  { id: "ecr-public", label: "ECR Public", icon: "service/AmazonElasticContainerRegistry", url: "public.ecr.aws", prefix: "ecr-public" },
  { id: "docker-hub", label: "Docker Hub", icon: "brand/docker", url: "registry-1.docker.io", prefix: "docker-hub", login: true },
  { id: "github-container-registry", label: "GitHub", icon: "brand/github", url: "ghcr.io", prefix: "github", login: true },
  { id: "gitlab-container-registry", label: "GitLab", icon: "brand/gitlab", url: "registry.gitlab.com", prefix: "gitlab", login: true },
  { id: "k8s", label: "Kubernetes", icon: "brand/kubernetes", url: "registry.k8s.io", prefix: "k8s" },
  { id: "quay", label: "Quay", icon: "brand/redhat", url: "quay.io", prefix: "quay" },
  { id: "chainguard", label: "Chainguard", icon: "brand/chainguard", url: "cgr.dev", prefix: "chainguard" },
  { id: "azure-container-registry", label: "Azure", icon: "", url: "myregistry.azurecr.io", prefix: "azure", login: true, own: true },
];

const expire = { type: "expire" };

/** Common lifecycle policies, as tiles over the policy editor. */
export const LIFECYCLE_PRESETS: { id: string; label: string; title: string; policy: object }[] = [
  {
    id: "tidy",
    label: "Tidy",
    title: "Expire untagged images after 14 days and keep the last 30",
    policy: {
      rules: [
        { rulePriority: 1, description: "Expire untagged images after 14 days", selection: { tagStatus: "untagged", countType: "sinceImagePushed", countUnit: "days", countNumber: 14 }, action: expire },
        { rulePriority: 2, description: "Keep the last 30 images", selection: { tagStatus: "any", countType: "imageCountMoreThan", countNumber: 30 }, action: expire },
      ],
    },
  },
  {
    id: "untagged",
    label: "Untagged",
    title: "Expire untagged images after a day",
    policy: { rules: [{ rulePriority: 1, description: "Expire untagged images after 1 day", selection: { tagStatus: "untagged", countType: "sinceImagePushed", countUnit: "days", countNumber: 1 }, action: expire }] },
  },
  {
    id: "keep-last",
    label: "Keep last 10",
    title: "Keep only the 10 newest images",
    policy: { rules: [{ rulePriority: 1, description: "Keep the last 10 images", selection: { tagStatus: "any", countType: "imageCountMoreThan", countNumber: 10 }, action: expire }] },
  },
  {
    id: "dev",
    label: "Dev builds",
    title: "Expire images tagged dev-* or pr-* after 7 days",
    policy: { rules: [{ rulePriority: 1, description: "Expire dev and PR builds after 7 days", selection: { tagStatus: "tagged", tagPatternList: ["dev-*", "pr-*"], countType: "sinceImagePushed", countUnit: "days", countNumber: 7 }, action: expire }] },
  },
];

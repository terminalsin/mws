/** The public repositories AWS can connect a repository to (AWS's names). */
export const EXTERNAL: [string, string][] = [
  ["public:npmjs", "npm"],
  ["public:pypi", "PyPI"],
  ["public:maven-central", "Maven Central"],
  ["public:maven-googleandroid", "Google Android"],
  ["public:maven-gradleplugins", "Gradle plugins"],
  ["public:maven-commonsware", "CommonsWare"],
  ["public:maven-clojars", "Clojars"],
  ["public:crates-io", "crates.io"],
  ["public:ruby-gems-org", "RubyGems"],
  ["public:nuget-org", "NuGet"],
];

/** Each connection's logo, package format and the repository name AWS's
 * console suggests for it (`npm-store`, ...). */
export const EXTERNAL_INFO: Record<string, { icon: string; format: string; name: string }> = {
  "public:npmjs": { icon: "brand/npm", format: "npm", name: "npm-store" },
  "public:pypi": { icon: "brand/pypi", format: "pypi", name: "pypi-store" },
  "public:maven-central": { icon: "brand/apachemaven", format: "maven", name: "maven-central-store" },
  "public:maven-googleandroid": { icon: "brand/android", format: "maven", name: "google-android-store" },
  "public:maven-gradleplugins": { icon: "brand/gradle", format: "maven", name: "gradle-plugins-store" },
  "public:maven-commonsware": { icon: "brand/apachemaven", format: "maven", name: "commonsware-store" },
  "public:maven-clojars": { icon: "brand/clojure", format: "maven", name: "clojars-store" },
  "public:crates-io": { icon: "brand/rust", format: "cargo", name: "crates-io-store" },
  "public:ruby-gems-org": { icon: "brand/rubygems", format: "ruby", name: "rubygems-store" },
  "public:nuget-org": { icon: "brand/nuget", format: "nuget", name: "nuget-store" },
};

export const externalIcon = (name: string | undefined) => (name ? EXTERNAL_INFO[name]?.icon : undefined);

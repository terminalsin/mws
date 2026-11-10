// What "Create function" offers as tiles: a language (its runtimes, newest
// first, and whether the console has starter code for it) or a container
// image. Plain data, shared by the server page and the client fields.

export interface RuntimePreset {
  id: string;
  label: string;
  icon: string;
  /** Runtimes, newest first; empty for a container image. */
  runtimes: string[];
  /** The console writes a hello-world handler, so no upload is needed. */
  starter?: boolean;
  /** What the uploaded package's handler usually looks like. */
  handler?: string;
}

export const RUNTIME_PRESETS: RuntimePreset[] = [
  { id: "nodejs", label: "Node.js", icon: "brand/nodedotjs", runtimes: ["nodejs22.x", "nodejs20.x"], starter: true },
  { id: "python", label: "Python", icon: "brand/python", runtimes: ["python3.13", "python3.12", "python3.11"], starter: true },
  { id: "ruby", label: "Ruby", icon: "brand/ruby", runtimes: ["ruby3.3"], starter: true },
  { id: "java", label: "Java", icon: "brand/openjdk", runtimes: ["java21", "java17"], handler: "example.Handler::handleRequest" },
  { id: "dotnet", label: ".NET", icon: "brand/dotnet", runtimes: ["dotnet8"], handler: "Assembly::Namespace.Function::FunctionHandler" },
  { id: "go", label: "Go", icon: "brand/go", runtimes: ["provided.al2023"], handler: "bootstrap" },
  { id: "rust", label: "Rust", icon: "brand/rust", runtimes: ["provided.al2023"], handler: "bootstrap" },
  { id: "provided", label: "Custom runtime", icon: "brand/linux", runtimes: ["provided.al2023"], handler: "bootstrap" },
  { id: "image", label: "Container image", icon: "brand/docker", runtimes: [] },
];

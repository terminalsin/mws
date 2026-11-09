"use server";

// Server actions over ./shell for the console's Terminal and FileExplorer.
import * as shell from "./shell";
import type { ShellTarget } from "./shell";

export async function shellExec(t: ShellTarget, command: string, cwd?: string) {
  return shell.exec(t, command, cwd);
}

export async function shellList(t: ShellTarget, path: string) {
  return shell.list(t, path);
}

export async function shellRead(t: ShellTarget, path: string) {
  return shell.read(t, path);
}

export async function shellWrite(t: ShellTarget, path: string, base64: string) {
  return shell.write(t, path, base64);
}

export async function shellRemove(t: ShellTarget, path: string) {
  return shell.remove(t, path);
}

export async function shellMkdir(t: ShellTarget, path: string) {
  return shell.mkdir(t, path);
}

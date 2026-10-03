import { execSync, execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { validateUrl } from "./urls.js";

const WORKSPACE = "/workspace";

export function diskUsage(dir: string): string {
  return execSync(`du -sh ${dir}`).toString();
}

export function diskUsageSafe(dir: string): string {
  return execFileSync("du", ["-sh", "--", dir]).toString();
}

export function readWorkspaceFile(name: string): string {
  return fs.readFileSync(path.join(WORKSPACE, name), "utf8");
}

export function readWorkspaceFileSafe(name: string): string {
  return fs.readFileSync(path.join(WORKSPACE, path.basename(name)), "utf8");
}

export async function fetchArgs(args: Record<string, unknown>): Promise<string> {
  const response = await fetch(String(args.url));
  return response.text();
}

export async function fetchArgsSafe(args: Record<string, unknown>): Promise<string> {
  const response = await fetch(validateUrl(String(args.url)));
  return response.text();
}

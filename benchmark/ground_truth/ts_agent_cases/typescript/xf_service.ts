import { execSync, execFileSync } from "child_process";

export class DiskService {
  constructor(private readonly root: string) {}

  usage(dir: string): string {
    return this.run(`du -sh ${this.root}/${dir}`);
  }

  usageSafe(dir: string): string {
    return execFileSync("du", ["-sh", "--", `${this.root}/${dir}`]).toString();
  }

  private run(command: string): string {
    return execSync(command).toString();
  }
}

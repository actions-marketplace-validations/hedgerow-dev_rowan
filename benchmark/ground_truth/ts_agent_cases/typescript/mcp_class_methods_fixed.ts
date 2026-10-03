import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import * as fs from "fs";
import * as path from "path";

const VECTOR_DIR = "/var/lib/solver/vectors";

export class SolverServer {
  private server = new Server({ name: "solver", version: "1.0.0" }, { capabilities: { tools: {} } });

  constructor() {
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      switch (name) {
        case "saveVectorToFile":
          return await this.handleSaveVector(args as any);
        default:
          throw new Error(`unknown tool ${name}`);
      }
    });
  }

  private async handleSaveVector(params: any) {
    const filePath = params.file_path;
    await this.saveVectorToFile(params.vector, filePath);
    return { content: [{ type: "text", text: "saved" }] };
  }

  private async saveVectorToFile(vector: number[], filePath: string): Promise<void> {
    const target = path.join(VECTOR_DIR, path.basename(filePath));
    fs.writeFileSync(target, JSON.stringify(vector));
  }
}

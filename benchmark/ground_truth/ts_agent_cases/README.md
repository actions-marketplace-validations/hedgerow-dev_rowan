# TypeScript agent-boundary cases

Paired fixtures for untrusted input entering TypeScript agent code: MCP tool
handlers (high-level `tool`/`registerTool` and the low-level
`CallToolRequestSchema` handler), Vercel AI SDK `tool({ execute })`,
LangChain.js `tool(...)`, and model output from `generateText` or the OpenAI
client. Every vulnerable file has a fixed control that uses a fix the scanner
can see: a validating helper's return value, `path.basename`, a parameterized
query, `execFile` with an argument array, or `JSON.parse`.

All fixtures were written for this project.

```bash
uv run python scripts/benchmark.py --corpus ts_agent_cases
```

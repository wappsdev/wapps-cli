// Dumps the plugin's tools/list (26 inputSchemas) as JSON, in memory, no daemon and no state.
// Run from a scratch copy of the plugin: bun tools_list.ts <path-to-plugin-src>
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
const { createMcpServer } = await import(`${process.argv[2]}/mcp/server.ts`);
const backend = { principal: { provider: "claude", sessionId: "s" }, assertMutation: async () => {}, execute: async () => null } as any;
const server = createMcpServer(backend);
const [a, b] = InMemoryTransport.createLinkedPair();
const client = new Client({ name: "probe", version: "0" });
await Promise.all([server.connect(a), client.connect(b)]);
console.log(JSON.stringify((await client.listTools()).tools));
process.exit(0);

import assert from "node:assert/strict";
import test from "node:test";
import { formatVersionReport, inspectToolVersions } from "./index.js";

test("reports installed and unavailable analyzers without making a scan", async () => {
  const tools = await inspectToolVersions([
    { id: "available", displayName: "Available", command: "available", args: ["--version"] },
    { id: "missing", displayName: "Missing", command: "missing", args: ["--version"] }
  ], async (command) => {
    if (command === "available") return "Available 1.2.3\n";
    throw new Error("not found");
  });
  assert.deepEqual(tools, [
    { id: "available", displayName: "Available", version: "Available 1.2.3", available: true },
    { id: "missing", displayName: "Missing", available: false }
  ]);
  assert.match(formatVersionReport("0.1.0", tools), /VulnWeave 0.1.0[\s\S]*Missing: not installed/);
});

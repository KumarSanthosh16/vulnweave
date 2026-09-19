import assert from "node:assert/strict";
import test from "node:test";
import { extractDependencyUsages, extractImports, extractSymbols } from "./index.js";

test("extracts TypeScript declaration symbols with one-based locations", () => {
  const symbols = extractSymbols("src/example.ts", "export class Service {\n  run() {}\n}\nfunction helper() {}\ninterface Config {}");
  assert.deepEqual(symbols.map((symbol) => [symbol.name, symbol.kind, symbol.line]), [["Service", "class", 1], ["run", "method", 2], ["helper", "function", 4], ["Config", "interface", 5]]);
  assert.equal(symbols[0]?.endLine, 3);
});

test("resolves local imports across emitted JavaScript extensions", () => {
  assert.deepEqual(extractImports("src/main.ts", 'import { helper } from "./helper.js";', new Set(["src/main.ts", "src/helper.ts"])), [{ from: "src/main.ts", to: "src/helper.ts", source: "./helper.js" }]);
});

test("extracts external package imports while excluding local and Node imports", () => {
  const usages = extractDependencyUsages("src/main.ts", 'import fp from "lodash/fp"; export { x } from "@scope/pkg/subpath"; const fs = require("node:fs"); const local = require("./local");');
  assert.deepEqual(usages.map((usage) => [usage.packageName, usage.source]), [["lodash", "lodash/fp"], ["@scope/pkg", "@scope/pkg/subpath"]]);
});

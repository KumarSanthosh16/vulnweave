import assert from "node:assert/strict";
import test from "node:test";
import { complexitySignals, duplicateSignals, extractDependencyUsages, extractImports, extractSymbols, functionDuplicateSignals, unreferencedFileSignals } from "./index.js";

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

test("reports repeated normalized blocks without treating whitespace as meaningful", () => {
  const source = "const one = 1;\nconst two = 2;\nconst three = 3;\nconst four = 4;\nconst five = 5;\nconst six = 6;";
  const signals = duplicateSignals([{ path: "src/first.ts", source }, { path: "src/second.ts", source: source.replace("const one", "  const one") }]);
  assert.equal(signals.length, 2);
  assert.equal(signals[0]?.kind, "duplicate-code");
  assert.equal(signals[0]?.relatedLocations?.[0]?.path, "src/second.ts");
});

test("reports high complexity functions while excluding nested function branches", () => {
  const source = "function review(value: number) { if (value) {} if (value) {} if (value) {} if (value) {} if (value) {} if (value) {} if (value) {} if (value) {} if (value) {} }";
  const [signal] = complexitySignals("src/review.ts", source);
  assert.equal(signal?.kind, "high-complexity");
  assert.equal(signal?.score, 10);
});

test("reports only non-entry files without observed local imports", () => {
  const signals = unreferencedFileSignals(["src/index.ts", "src/used.ts", "src/orphan.ts"], [{ from: "src/index.ts", to: "src/used.ts", source: "./used" }]);
  assert.deepEqual(signals.map((signal) => signal.path), ["src/orphan.ts"]);
});

test("reports duplicate parsed function bodies", () => {
  const source = "function first() {\n const answer = 42;\n return answer;\n}\nfunction second() {\n const answer = 42;\n return answer;\n}";
  assert.equal(functionDuplicateSignals([{ path: "src/example.ts", source }]).length, 2);
});

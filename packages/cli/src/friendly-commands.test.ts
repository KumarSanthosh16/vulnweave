import assert from "node:assert/strict";
import test from "node:test";
import { expandFriendlyCommand } from "./friendly-commands.js";

test("expands compact scan and report commands", () => {
  assert.deepEqual(expandFriendlyCommand(["scan", "."]), [".", "--format", "summary"]);
  assert.deepEqual(expandFriendlyCommand(["--", "scan", "."]), ["--", ".", "--format", "summary"]);
  assert.deepEqual(expandFriendlyCommand(["report", "."]), [".", "--format", "html"]);
});

test("expands review base reference and CI health requirements", () => {
  assert.deepEqual(expandFriendlyCommand(["review", ".", "--base", "main"]), [".", "--changed-since", "main", "--review-changes", "--format", "review"]);
  assert.deepEqual(expandFriendlyCommand(["ci", "."]), [".", "--format", "summary", "--require-analyzers"]);
});

test("leaves advanced commands untouched and maps doctor to version", () => {
  assert.deepEqual(expandFriendlyCommand([".", "--format", "sarif"]), [".", "--format", "sarif"]);
  assert.deepEqual(expandFriendlyCommand(["doctor"]), ["--version"]);
});

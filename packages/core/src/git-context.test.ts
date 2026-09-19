import assert from "node:assert/strict";
import test from "node:test";
import { changedPaths } from "./index.js";

test("returns no change context for a non-Git directory", async () => {
  assert.deepEqual(await changedPaths("/private/tmp"), []);
});

import assert from "node:assert/strict";
import test from "node:test";
import { pythonDependencyUpdateGuidance } from "./index.js";

test("gives Python package-manager guidance without instructing users to edit a lockfile", () => {
  assert.match(pythonDependencyUpdateGuidance("requests", "2.32.0", "requirements.txt", "PyPI") ?? "", /requirements\.txt/);
  assert.match(pythonDependencyUpdateGuidance("requests", "2.32.0", "services/api/poetry.lock", "PyPI") ?? "", /services\/api\/pyproject\.toml.*poetry lock/);
  assert.match(pythonDependencyUpdateGuidance("requests", "2.32.0", "Pipfile.lock", "PyPI") ?? "", /Pipfile.*pipenv lock/);
  assert.match(pythonDependencyUpdateGuidance("requests", "2.32.0", "uv.lock", "PyPI") ?? "", /pyproject\.toml.*uv lock/);
});

test("does not apply Python advice to other dependency ecosystems", () => {
  assert.equal(pythonDependencyUpdateGuidance("lodash", "4.17.22", "package-lock.json", "npm"), undefined);
});

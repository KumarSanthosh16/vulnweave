import { cp, mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const cliDirectory = resolve(fileURLToPath(new URL("..", import.meta.url)));
const repositoryDirectory = resolve(cliDirectory, "../..");

await mkdir(resolve(cliDirectory, "rules"), { recursive: true });
await cp(resolve(repositoryDirectory, "rules"), resolve(cliDirectory, "rules"), { recursive: true, force: true });
for (const file of ["LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"]) {
  await cp(resolve(repositoryDirectory, file), resolve(cliDirectory, file), { force: true });
}

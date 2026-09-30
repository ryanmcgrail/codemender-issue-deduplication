import { readdir, readFile } from "node:fs/promises";

import { generateFingerprint, parseFindingsJson, type Finding } from "./code.ts";

interface Session {
  path: string;
  findings: Finding[];
}

const findingsJsonFiles: string[] = (
  await readdir("results", { recursive: true })
).filter((file) => file.endsWith("findings.json"));
const sessions: readonly Session[] = (
  await Promise.all(
    findingsJsonFiles.map(
      async (path) => {
        const contents = await readFile(`results/${path}`, "utf8");
        const findings = parseFindingsJson(contents);
        if (!!findings) {
          return { path, findings };
        }
        return null;
      }
    ),
  )
)
  .filter((o) => !!o)
  .sort((a, b) => a.path.localeCompare(b.path));

describe("tests", () => {
  for (const session of sessions) {
    it(`handles session ${session.path}`, async () => {     
      for (const finding of session.findings) {
        await generateFingerprint(finding);
      }
    });
  }
});
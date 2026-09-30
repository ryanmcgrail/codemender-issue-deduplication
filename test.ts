import { generateFingerprint } from "./finding.ts";
import { sessionsByVersionAndRepo } from "./sessions.ts";

for (const [versionAndRepo, sessions] of sessionsByVersionAndRepo) {
  it(`handles ${versionAndRepo}`, async () => {
    for (const finding of session.findings) {
      await generateFingerprint(finding);
    }
  });
}
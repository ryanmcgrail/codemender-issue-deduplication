import {
  Finding,
  generateFingerprintCodeMender,
  generateFingerprintJf,
} from "./finding.ts";
import { sessionsByVersionAndRepo } from "./sessions.ts";

await evaluateFingerprintMethod(
  generateFingerprintCodeMender.name,
  generateFingerprintCodeMender,
);
await evaluateFingerprintMethod(
  generateFingerprintJf.name,
  generateFingerprintJf
);

async function evaluateFingerprintMethod(
  methodName: string,
  fingerprintMethod: (finding: Finding) => Promise<string>,
) {
  console.log(`Evaluating fingerprint method: ${methodName}`);

  let duplicateCountForRepo = 0;
  let duplicateCountForVersion = 0;
  let duplicateCountForSingleSession = 0;

  const fingerprintsByRepo = new Map<string, Set<string>>();

  for (const [versionAndRepo, sessions] of sessionsByVersionAndRepo) {
    const repo = versionAndRepo.split("/").pop()!;

    let fingerprintsForRepo: Set<string>;
    if (fingerprintsByRepo.has(repo)) {
      fingerprintsForRepo = fingerprintsByRepo.get(repo)!;
    } else {
      fingerprintsForRepo = new Set<string>();
      fingerprintsByRepo.set(repo, fingerprintsForRepo);
    }

    const fingerprintsForVersion = new Set<string>();

    for (const session of sessions) {
      const fingerprintsForSession = new Set<string>();

      for (const finding of session.findings) {
        const fingerprint = await fingerprintMethod(finding);

        if (fingerprintsForRepo.has(fingerprint)) {
          duplicateCountForRepo++;
        } else {
          fingerprintsForRepo.add(fingerprint);
        }

        if (fingerprintsForVersion.has(fingerprint)) {
          duplicateCountForVersion++;
        } else {
          fingerprintsForVersion.add(fingerprint);
        }

        if (fingerprintsForSession.has(fingerprint)) {
          duplicateCountForSingleSession++;
        } else {
          fingerprintsForSession.add(fingerprint);
        }
      }
    }
  }

  console.log(`  Duplicate count for repos: ${duplicateCountForRepo}`);
  console.log(
    `  Duplicate count within the same version: ${duplicateCountForVersion}`,
  );
  console.log(
    `  Duplicate count within the same session: ${duplicateCountForSingleSession}`,
  );
}

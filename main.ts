import { Finding } from "./finding.ts";
import {
  GenerateFingerprintMethod,
  GENERATE_FINGERPRINT_METHODS,
} from "./generate_fingerprint.ts";
import { sessionsByVersionAndRepo } from "./results.ts";
import { SessionSummary } from "./session_summary.ts";

class FindingsByFingerprint {
  private impl_ = new Map<string, Finding[]>();
  private duplicateCount_ = 0;

  constructor(
    private readonly generateFingerprint: GenerateFingerprintMethod,
  ) {}

  async add(finding: Finding, sessionSummary: SessionSummary) {
    const fingerprint = await this.generateFingerprint(finding, sessionSummary);
    if (!this.impl_.has(fingerprint)) {
      this.impl_.set(fingerprint, []);
    } else {
      this.duplicateCount_++;
    }
    this.impl_.get(fingerprint)!.push(finding);
  }

  removeSingletons() {
    const singletonFingerprints = [...this.impl_.entries()]
      .filter(([, value]) => value.length == 1)
      .map(([key]) => key);

    for (const singletonFingerprint of singletonFingerprints) {
      this.impl_.delete(singletonFingerprint);
    }
  }

  get duplicateCount(): number {
    return this.duplicateCount_;
  }

  toString(): string {
    return convertMapToString(this.impl_);
  }
}

for (const generateFingerprint of GENERATE_FINGERPRINT_METHODS) {
  await evaluateFingerprintMethod(
    generateFingerprint.name,
    generateFingerprint,
  );
}

async function evaluateFingerprintMethod(
  methodName: string,
  generateFingerprint: GenerateFingerprintMethod,
) {
  console.log(`Evaluating fingerprint method: ${methodName}`);

  const findingsByFingerprintByRepo = new Map<string, FindingsByFingerprint>();

  let findingCount = 0;
  let duplicateCountForVersion = 0;
  let duplicateCountForSingleSession = 0;

  for (const [versionAndRepo, sessions] of sessionsByVersionAndRepo) {
    const repo = versionAndRepo.split("/").pop()!;

    let findingsByFingerprintForRepo: FindingsByFingerprint;
    if (findingsByFingerprintByRepo.has(repo)) {
      findingsByFingerprintForRepo = findingsByFingerprintByRepo.get(repo)!;
    } else {
      findingsByFingerprintForRepo = new FindingsByFingerprint(
        generateFingerprint,
      );
      findingsByFingerprintByRepo.set(repo, findingsByFingerprintForRepo);
    }

    const fingerprintsForVersion = new Set<string>();

    for (const session of sessions) {
      const fingerprintsForSession = new Set<string>();

      for (const finding of session.findings) {
        const fingerprint = await generateFingerprint(
          finding,
          session.sessionSummary,
        );
        ++findingCount;

        await findingsByFingerprintForRepo.add(finding, session.sessionSummary);

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

  console.log(`  Total finding count for repos: ${findingCount}`);
  console.log(
    `  Duplicate count for repos: ${Array.from(findingsByFingerprintByRepo.values()).reduce((sum, f) => sum + f.duplicateCount, 0)}`,
  );
  console.log(
    `  Duplicate count within the same version: ${duplicateCountForVersion}`,
  );
  console.log(
    `  Duplicate count within the same session: ${duplicateCountForSingleSession}`,
  );

  if (false) {
    for (const findingsByFingerprint of findingsByFingerprintByRepo.values()) {
      findingsByFingerprint.removeSingletons();
    }

    console.log(indentString(convertMapToString(findingsByFingerprintByRepo)));
  }
}

function convertMapToString<TKey, TValue>(map: Map<TKey, TValue>): string {
  let text = "{\n";

  for (const [key, value] of map) {
    text += indentString(`${key}: ${convertAnyToString(value)},`);
  }

  text += "}";

  return text;
}

function convertArrayToString<T>(array: T[]): string {
  let text = "[\n";

  for (const element of array) {
    text += indentString(`${convertAnyToString(element)},`);
  }

  text += "]";

  return text;
}

function convertAnyToString<T>(obj: any): string {
  if (obj instanceof Array) {
    return convertArrayToString(obj);
  }

  if (obj instanceof Map) {
    return convertMapToString(obj);
  }

  if (obj instanceof FindingsByFingerprint) {
    return `${obj}`;
  }

  if ("snippet" in obj) {
    const finding = obj as Finding;
    return `{ 
  filePath: "${finding.filePath}",
}`;
  }

  return JSON.stringify(obj, null, 2);
}

function indentString(text: string): string {
  return (
    text
      .split("\n")
      .map((line) => `  ${line}`)
      .join("\n") + "\n"
  );
}

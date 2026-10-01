import {
  Finding,
  generateFingerprintCodeMender,
  generateFingerprintJf,
} from "./finding.ts";
import { sessionsByVersionAndRepo } from "./sessions.ts";

type FingerprintMethod = (finding: Finding) => Promise<string>;

class FindingsByFingerprint {
  private impl_ = new Map<string, Finding[]>();
  private duplicateCount_ = 0;

  constructor(private readonly fingerprintMethod: FingerprintMethod) {  }

  async add(finding: Finding) {
    const fingerprint = await this.fingerprintMethod(finding);
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
  fingerprintMethod: FingerprintMethod,
) {
  console.log(`Evaluating fingerprint method: ${methodName}`);

  const findingsByFingerprintByRepo = new Map<string, FindingsByFingerprint>();

  let duplicateCountForVersion = 0;
  let duplicateCountForSingleSession = 0;

  for (const [versionAndRepo, sessions] of sessionsByVersionAndRepo) {
    const repo = versionAndRepo.split("/").pop()!;

    let findingsByFingerprintForRepo: FindingsByFingerprint;
    if (findingsByFingerprintByRepo.has(repo)) {
      findingsByFingerprintForRepo = findingsByFingerprintByRepo.get(repo)!;
    } else {
      findingsByFingerprintForRepo = new FindingsByFingerprint(fingerprintMethod);
      findingsByFingerprintByRepo.set(repo, findingsByFingerprintForRepo);
    }

    const fingerprintsForVersion = new Set<string>();

    for (const session of sessions) {
      const fingerprintsForSession = new Set<string>();

      for (const finding of session.findings) {
        const fingerprint = await fingerprintMethod(finding);

        await findingsByFingerprintForRepo.add(finding);

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

  for (const findingsByFingerprint of findingsByFingerprintByRepo.values()) {
    findingsByFingerprint.removeSingletons();
  }

  console.log(
    `  Duplicate count for repos: ${Array.from(findingsByFingerprintByRepo.values()).reduce((sum, f) => sum + f.duplicateCount, 0)}`,
  );
  console.log(
    `  Duplicate count within the same version: ${duplicateCountForVersion}`,
  );
  console.log(
    `  Duplicate count within the same session: ${duplicateCountForSingleSession}`,
  );
  console.log(indentString(convertMapToString(findingsByFingerprintByRepo)));
}

function convertMapToString<TKey, TValue>(map: Map<TKey, TValue>): string {
  let text = "{\n";

  for (const [key, value] of map) {
    text += indentString(`${key}: ${convertAnyToString(value)},`);
  }

  text += '}';

  return text;
}

function convertArrayToString<T>(array: T[]): string {
  let text = "[\n";

  for (const element of array) {
    text += indentString(`${convertAnyToString(element)},`);
  }

  text += ']';

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
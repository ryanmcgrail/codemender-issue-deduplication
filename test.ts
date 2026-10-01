import {
  generateFingerprintJf,
  generateFingerprintCodeMender,
  Finding,
} from "./finding.ts";

const SAMPLE_FINDING_1: Finding = {
  filePath: "abc/xyz",
  vulnerabilityId: "CWE-123",
  snippet: "sample snippet",
};

const SAMPLE_FINDING_2: Finding = {
  filePath: "foo/bar",
  vulnerabilityId: "CWE-456",
  snippet: "different snippet",
};

describe("tests", () => {
  pdescribe(
    "fingerprint methods",
    {
      generateFingerprintCodeMender: generateFingerprintCodeMender,
      generateFingerprintJf: generateFingerprintJf,
    },
    (fingerprintMethod) => {
      pit(
        "supports obvious matches",
        {
          "same object": {
            lhs: SAMPLE_FINDING_1,
            rhs: SAMPLE_FINDING_1,
            expectedResult: true,
          },
          "different objects": {
            lhs: SAMPLE_FINDING_1,
            rhs: SAMPLE_FINDING_2,
            expectedResult: false,
          },
        },
        async ({ lhs, rhs, expectedResult }) => {
          const lhsFingerprint = await fingerprintMethod(lhs);
          const rhsFingerprint = await fingerprintMethod(rhs);
          expect(lhsFingerprint === rhsFingerprint).toBe(expectedResult);
        },
      );
    },
  );
});

function pit<T>(
  name: string,
  cases: Record<string, T>,
  fn: (value: T) => Promise<void>,
) {
  for (const [caseName, value] of Object.entries(cases)) {
    it(`${name} - ${caseName}`, async () => {
      await fn(value);
    });
  }
}

function pdescribe<T>(
  name: string,
  cases: Record<string, T>,
  fn: (value: T) => void,
) {
  for (const [caseName, value] of Object.entries(cases)) {
    describe(`${name} - ${caseName}`, () => {
      fn(value);
    });
  }
}

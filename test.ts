import { GENERATE_FINGERPRINT_METHODS, GenerateFingerprintMethod } from "./finding.ts";

const GENERATE_FINGERPRINT_CASES: Record<string, GenerateFingerprintMethod> = {};
for (const generateFingerprint of GENERATE_FINGERPRINT_METHODS) {
  GENERATE_FINGERPRINT_CASES[generateFingerprint.name] = generateFingerprint;
}

describe("tests", () => {
  pdescribe(
    "fingerprint methods",
    GENERATE_FINGERPRINT_CASES,
    (fingerprintMethod) => {
      pit(
        "supports obvious matches",
        {
          "same finding": {
            lhs: {
              filePath: "abc/xyz",
              vulnerabilityId: "CWE-123",
              snippet: "sample snippet",
            },
            rhs: {
              filePath: "abc/xyz",
              vulnerabilityId: "CWE-123",
              snippet: "sample snippet",
            },
            expectedResult: true,
          },
          "different findings": {
            lhs: {
              filePath: "abc/xyz",
              vulnerabilityId: "CWE-123",
              snippet: "sample snippet",
            },
            rhs: {
              filePath: "foo/bar",
              vulnerabilityId: "CWE-456",
              snippet: "different snippet",
            },
            expectedResult: false,
          },
          "equivalent findings": {
            lhs: {
              filePath: "ABC\\XYZ",
              vulnerabilityId: "CWE-80",
              snippet: "  sample  \t \n  snippet  ",
            },
            rhs: {
              filePath: "abc/xyz",
              vulnerabilityId: "cwe-80",
              snippet: "sample snippet",
            },
            expectedResult: true,
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

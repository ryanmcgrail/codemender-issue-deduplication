import { GENERATE_FINGERPRINT_METHODS, GenerateFingerprintMethod } from "./generate_fingerprint.ts";
import { Finding } from "./finding.ts";
import { SessionSummary } from "./session_summary.ts";

const GENERATE_FINGERPRINT_CASES: Record<string, GenerateFingerprintMethod> = {};
for (const generateFingerprint of GENERATE_FINGERPRINT_METHODS) {
  GENERATE_FINGERPRINT_CASES[generateFingerprint.name] = generateFingerprint;
}

interface FindingAndSessionSummary {
  finding: Finding;
  sessionSummary: SessionSummary;
}

describe("tests", () => {
  pdescribe(
    "fingerprint methods",
    GENERATE_FINGERPRINT_CASES,
    (generateFingerprint) => {
      pit<{
        lhs: FindingAndSessionSummary;
        rhs: FindingAndSessionSummary;
        expectedResult: boolean;
      }>(
        "supports obvious matches",
        {
          "same finding": {
            lhs: {
              finding: {
                filePath: "abc/xyz",
                vulnerabilityId: "CWE-123",
                snippet: "sample snippet",
              },
              sessionSummary: { working_dir: "" },
            },
            rhs: {
              finding: {
                filePath: "abc/xyz",
                vulnerabilityId: "CWE-123",
                snippet: "sample snippet",
              },
              sessionSummary: { working_dir: "" },
            },
            expectedResult: true,
          },
          "different findings": {
            lhs: {
              finding: {
                filePath: "abc/xyz",
                vulnerabilityId: "CWE-123",
                snippet: "sample snippet",
              },
              sessionSummary: { working_dir: "" },
            },
            rhs: {
              finding: {
                filePath: "foo/bar",
                vulnerabilityId: "CWE-456",
                snippet: "different snippet",
              },
              sessionSummary: { working_dir: "" },
            },
            expectedResult: false,
          },
          "equivalent findings": {
            lhs: {
              finding: {
                filePath: "ABC\\XYZ",
                vulnerabilityId: "CWE-80",
                snippet: "  sample  \t \n  snippet  ",
              },
              sessionSummary: { working_dir: "" },
            },
            rhs: {
              finding: {
                filePath: "abc/xyz",
                vulnerabilityId: "cwe-80",
                snippet: "sample snippet",
              },
              sessionSummary: { working_dir: "" },
            },
            expectedResult: true,
          },
          "equivalent paths": {
            lhs: {
              finding: {
                filePath: "root/abc/xyz",
                vulnerabilityId: "CWE-80",
                snippet: "sample snippet",
              },
              sessionSummary: { working_dir: "root/" },
            },
            rhs: {
              finding: {
                filePath: "abc/xyz",
                vulnerabilityId: "CWE-80",
                snippet: "sample snippet",
              },
              sessionSummary: { working_dir: "" },
            },
            expectedResult: true,
          },
        },
        async ({ lhs, rhs, expectedResult }) => {
          const lhsFingerprint = await generateFingerprint(lhs.finding, lhs.sessionSummary);
          const rhsFingerprint = await generateFingerprint(rhs.finding, rhs.sessionSummary);
          expect(lhsFingerprint === rhsFingerprint).toBe(expectedResult);
        },
      );

    pit('supports different path cases', {
        "same path after removing root": {
          lhs: {filePath: "abc/xyz", working_dir: ''},
          rhs: {filePath: "root/abc/xyz", working_dir: 'root/'},
          expectedResult: true,
        },
        "same path after removing root, missing forward slash": {
          lhs: {filePath: "abc/xyz", working_dir: ''},
          rhs: {filePath: "root/abc/xyz", working_dir: 'root'},
          expectedResult: true,
        }
      },
      async ({lhs, rhs, expectedResult}) => {
        const lhsFingerprint = await generateFingerprint({filePath: lhs.filePath, vulnerabilityId: 'CWE-123', snippet: 'foobar'}, {working_dir: lhs.working_dir});
        const rhsFingerprint = await generateFingerprint({filePath: rhs.filePath, vulnerabilityId: 'CWE-123', snippet: 'foobar'}, {working_dir: rhs.working_dir});
        expect(lhsFingerprint === rhsFingerprint).toBe(expectedResult);
      }
    );
  });
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

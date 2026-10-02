import {
  GENERATE_FINGERPRINT_METHODS,
  GenerateFingerprintMethod,
  normalizeFilePathV2,
  normalizeSnippetV2,
} from "./generate_fingerprint.ts";
import { Finding } from "./finding.ts";
import { SessionSummary } from "./session_summary.ts";

const GENERATE_FINGERPRINT_CASES: Record<string, GenerateFingerprintMethod> =
  {};
for (const generateFingerprint of GENERATE_FINGERPRINT_METHODS) {
  GENERATE_FINGERPRINT_CASES[generateFingerprint.name] = generateFingerprint;
}

interface FindingAndSessionSummary {
  finding: Finding;
  sessionSummary: SessionSummary;
}

describe("tests", () => {
  describe("normalizing", () => {
    pit(
      "supports normalizing file paths",
      {
        "normalizes slashes": {
          filePath: "abc\\xyz/foo\\bar",
          expectedOutput: "abc/xyz/foo/bar",
        },
        "removes root from start (with slash in root)": {
          filePath: "abc/xyz/foo/bar",
          rootFilePath: "abc/",
          expectedOutput: "xyz/foo/bar",
        },
        "removes root from start (without slash in root)": {
          filePath: "abc\\xyz/foo\\bar",
          rootFilePath: "abc",
          expectedOutput: "xyz/foo/bar",
        },
        "does not remove root if in middle": {
          filePath: "abc\\xyz/foo\\bar",
          rootFilePath: "xyz",
          expectedOutput: "abc/xyz/foo/bar",
        },
      },
      ({ filePath, rootFilePath, expectedOutput }) => {
        expect(normalizeFilePathV2(filePath, rootFilePath)).toBe(
          expectedOutput,
        );
      },
    );

    pit(
      "supports normalizing snippets",
      {
        "normalizes whitespace": {
          input: "  \t \n foo  \n  \t bar \t ",
          expectedOutput: "foo bar",
        },
        "removes line comments": {
          input: "  // foo \n bar ",
          expectedOutput: "bar",
        },
        "removes inline block comments": {
          input: "  /* foo */ bar ",
          expectedOutput: "bar",
        },
        "removes multiline block comments": {
          input: "  /* foo \n */ bar ",
          expectedOutput: "bar",
        },
      },
      ({ input, expectedOutput }) => {
        expect(normalizeSnippetV2(input)).toBe(expectedOutput);
      },
    );
  });

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
          const lhsFingerprint = await generateFingerprint(
            lhs.finding,
            lhs.sessionSummary,
          );
          const rhsFingerprint = await generateFingerprint(
            rhs.finding,
            rhs.sessionSummary,
          );
          expect(lhsFingerprint === rhsFingerprint).toBe(expectedResult);
        },
      );

      pit(
        "supports different path cases",
        {
          "same path after removing root": {
            lhs: { filePath: "abc/xyz", working_dir: "" },
            rhs: { filePath: "root/abc/xyz", working_dir: "root/" },
            expectedResult: true,
          },
          "same path after removing root, missing forward slash": {
            lhs: { filePath: "abc/xyz", working_dir: "" },
            rhs: { filePath: "root/abc/xyz", working_dir: "root" },
            expectedResult: true,
          },
        },
        async ({ lhs, rhs, expectedResult }) => {
          const lhsFingerprint = await generateFingerprint(
            {
              filePath: lhs.filePath,
              vulnerabilityId: "CWE-123",
              snippet: "foobar",
            },
            { working_dir: lhs.working_dir },
          );
          const rhsFingerprint = await generateFingerprint(
            {
              filePath: rhs.filePath,
              vulnerabilityId: "CWE-123",
              snippet: "foobar",
            },
            { working_dir: rhs.working_dir },
          );
          expect(lhsFingerprint === rhsFingerprint).toBe(expectedResult);
        },
      );
    },
  );
});

type CaseHandler<T> = (value: T) => void | Promise<void>;

function pit<T>(name: string, cases: Record<string, T>, fn: CaseHandler<T>) {
  for (const [caseName, value] of Object.entries(cases)) {
    it(`${name} - ${caseName}`, async () => {
      await fn(value);
    });
  }
}

function pdescribe<T>(
  name: string,
  cases: Record<string, T>,
  fn: CaseHandler<T>,
) {
  for (const [caseName, value] of Object.entries(cases)) {
    describe(`${name} - ${caseName}`, () => {
      fn(value);
    });
  }
}

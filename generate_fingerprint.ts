import { Finding } from "./finding.ts";
import { SessionSummary } from "./session_summary.ts";

export enum CweFamilyType {
  CodeInjection,
  CommandInjection,
  CrossSiteScripting,
  Deserialization,
  HardcodedSecret,
  JwtSignatureBypass,
  PathTraversal,
  ServerSideRequestForgery,
  SessionExpiration,
  SqlInjection,
  WeakCrypto,
  XmlExternalEntity,
}

const CWE_FAMILIES: ReadonlyMap<CweFamilyType, number[]> = new Map<
  CweFamilyType,
  number[]
>([
  [CweFamilyType.CodeInjection, [94, 95, 96]],
  [CweFamilyType.CommandInjection, [77, 78, 88]],
  [CweFamilyType.CrossSiteScripting, [79, 80, 83]],
  [CweFamilyType.Deserialization, [502]],
  [CweFamilyType.HardcodedSecret, [259, 798]],
  [CweFamilyType.JwtSignatureBypass, [347]],
  [CweFamilyType.PathTraversal, [22, 23, 36, 73, 434]],
  [CweFamilyType.ServerSideRequestForgery, [918]],
  [CweFamilyType.SessionExpiration, [613]],
  [CweFamilyType.SqlInjection, [89, 564, 943]],
  [CweFamilyType.WeakCrypto, [327, 328]],
  [CweFamilyType.XmlExternalEntity, [611, 776]],
]);

const CWE_FAMILY_BY_ID: ReadonlyMap<number, CweFamilyType> = new Map<
  number,
  CweFamilyType
>(
  [...CWE_FAMILIES.entries()].flatMap(([key, values]) =>
    values.map((v) => [v, key]),
  ),
);

function normalizeFilePath(filePath: string): string {
  return filePath.trim().replace(/\\/g, "/").toLowerCase();
}

export function normalizeFilePathV2(
  filePath: string,
  rootFilePath: string = "",
): string {
  let normalized = filePath.trim().replace(/\\/g, "/").toLowerCase();

  if (normalized.startsWith(rootFilePath)) {
    normalized = normalized.slice(rootFilePath.length);
  }

  if (normalized.startsWith("/")) {
    normalized = normalized.slice(1);
  }
  if (normalized.endsWith("/")) {
    normalized = normalized.slice(0, -1);
  }

  return normalized;
}

function normalizeVulnerabilityId(vulnerabilityId: string): string {
  return vulnerabilityId.trim().toLowerCase();
}

function normalizeSnippet(snippet: string): string {
  return snippet.trim().replace(/\s+/g, " ");
}

export function normalizeSnippetV2(snippet: string): string {
  const outSnippet = snippet
    .replace(/\/\/.*$/gm, "")
    .replace(/\s+/g, " ")
    .replace(/\/\*.*?\*\//g, "")
    .trim();

  if (outSnippet.length == 0) {
    console.log("WARNING: Empty snippet");
    console.log(`  Original snippet: ${snippet}`);
  }

  return outSnippet;
}

async function getSha256Hash(text: string): Promise<string> {
  const msgUint8 = new TextEncoder().encode(text);

  const hashBuffer = await globalThis.crypto.subtle.digest("SHA-256", msgUint8);

  const hashArray = Array.from(new Uint8Array(hashBuffer));

  const hashHex = hashArray
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return hashHex;
}

export type GenerateFingerprintMethod = (
  finding: Finding,
  sessionSummary: SessionSummary,
) => Promise<string>;

export async function generateFingerprintCodeMender(
  finding: Finding,
  sessionSummary: SessionSummary,
): Promise<string> {
  const normalizedFilePath = normalizeFilePathV2(
    finding.filePath,
    sessionSummary.working_dir,
  );
  const normalizedVulnerabilityId = normalizeVulnerabilityId(
    finding.vulnerabilityId,
  );
  const normalizedSnippet = normalizeSnippet(finding.snippet);

  return await getSha256Hash(
    normalizedFilePath + normalizedVulnerabilityId + normalizedSnippet,
  );
}

export async function generateFingerprintJf(
  finding: Finding,
  sessionSummary: SessionSummary,
): Promise<string> {
  const normalizedFilePath = normalizeFilePathV2(
    finding.filePath,
    sessionSummary.working_dir,
  );
  const vulnerabilityIdNumber = parseInt(finding.vulnerabilityId.split("-")[1]);
  const vulnerabilityFamily = CWE_FAMILY_BY_ID.get(vulnerabilityIdNumber);
  const normalizedSnippet = normalizeSnippet(finding.snippet);

  return await getSha256Hash(
    normalizedFilePath + vulnerabilityFamily + normalizedSnippet,
  );
}

export async function generateFingerprintWithoutVulnerabilityId(
  finding: Finding,
  sessionSummary: SessionSummary,
): Promise<string> {
  const normalizedFilePath = normalizeFilePathV2(
    finding.filePath,
    sessionSummary.working_dir,
  );
  const normalizedSnippet = normalizeSnippet(finding.snippet);

  return await getSha256Hash(normalizedFilePath + normalizedSnippet);
}

export async function generateFingerprintDebug(
  finding: Finding,
  sessionSummary: SessionSummary,
): Promise<string> {
  const normalizedFilePath = normalizeFilePathV2(
    finding.filePath,
    sessionSummary.working_dir,
  );
  const normalizedSnippet = normalizeSnippetV2(finding.snippet);

  return await getSha256Hash(normalizedFilePath + normalizedSnippet);
}

export const GENERATE_FINGERPRINT_METHODS: GenerateFingerprintMethod[] = [
  generateFingerprintCodeMender,
  generateFingerprintJf,
  generateFingerprintWithoutVulnerabilityId,
  generateFingerprintDebug,
];

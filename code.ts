interface CmFindingV1 {
  Snippet: string;
  VulnID: string;
  FilePath: string;
}

function isCmFindingV1(finding: any): finding is CmFindingV1 {
  return "Snippet" in finding && "VulnID" in finding && "FilePath" in finding;
}

interface CmFindingV2 {
  file_path: string;
  vuln_id: string;
  snippet: string;
}

function isCmFindingV2(finding: any): finding is CmFindingV2 {
  return "snippet" in finding && "vuln_id" in finding && "file_path" in finding;
}

export interface Finding {
  filePath: string;
  vulnerabilityId: string;
  snippet: string;
}

function tryToNormalizeFinding(finding: any): Finding | null {
  if (isCmFindingV1(finding)) {
    return {
      filePath: finding.FilePath,
      vulnerabilityId: finding.VulnID,
      snippet: finding.Snippet,
    };
  } 
  
  if (isCmFindingV2(finding)) {
     return {
       filePath: finding.file_path,
       vulnerabilityId: finding.vuln_id,
       snippet: finding.snippet,
     };
   }

   return null;
}

export function parseFindingsJson(jsonString: string): Finding[] | null {
  const cmFindings = JSON.parse(jsonString) as any[];
  if (!cmFindings) {
    return null;
  }
  
  const findings = cmFindings.map((finding) => tryToNormalizeFinding(finding)).filter((f) => f !== null);
  if (findings.length === 0) {
    return null;
  }

  return findings;
}

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

const CWE_FAMILIES: ReadonlyMap<CweFamilyType, number[]> = new Map<CweFamilyType, number[]>([
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

function normalizeVulnerabilityId(vulnerabilityId: string): string {
    return vulnerabilityId.toLowerCase().trim();
}

function normalizeSnippet(snippet: string): string {
    return snippet.trim().replace(/\s+/g, " ");
}

async function getSha256Hash(text: string): Promise<string> {
  const msgUint8 = new TextEncoder().encode(text);
  
  const hashBuffer = await globalThis.crypto.subtle.digest("SHA-256", msgUint8);
  
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  
  const hashHex = hashArray
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
    
  return hashHex;
};
  
export async function generateFingerprint(finding: Finding): Promise<string> {
    const normalizedVulnerabilityId = normalizeVulnerabilityId(finding.vulnerabilityId);
    const normalizedSnippet = normalizeSnippet(finding.snippet);

    return await getSha256Hash(finding.filePath + normalizedVulnerabilityId + normalizedSnippet);
}
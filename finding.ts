export interface Finding {
  filePath: string;
  vulnerabilityId: string;
  snippet: string;
  original?: any;
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

const CWE_FAMILY_BY_ID: ReadonlyMap<number, CweFamilyType> 
= new Map<number, CweFamilyType>([...CWE_FAMILIES.entries()].flatMap(([key, values]) => values.map((v) => [v, key]))) ;

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
  
export async function generateFingerprintCodeMender(finding: Finding): Promise<string> {
    const normalizedVulnerabilityId = normalizeVulnerabilityId(finding.vulnerabilityId);
    const normalizedSnippet = normalizeSnippet(finding.snippet);

    return await getSha256Hash(finding.filePath + normalizedVulnerabilityId + normalizedSnippet);
}

export async function generateFingerprintJf(finding: Finding): Promise<string> {
    const vulnerabilityIdNumber = parseInt(finding.vulnerabilityId.split("-")[1]);
    const vulnerabilityFamily = CWE_FAMILY_BY_ID.get(vulnerabilityIdNumber);
    const normalizedSnippet = normalizeSnippet(finding.snippet);

    return await getSha256Hash(finding.filePath + vulnerabilityFamily + normalizedSnippet);
}
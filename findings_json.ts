import { type Finding } from "./finding.ts";

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

function tryToNormalizeFinding(finding: any): Finding | null {
  if (isCmFindingV1(finding)) {
    return {
      filePath: finding.FilePath,
      vulnerabilityId: finding.VulnID,
      snippet: finding.Snippet,
      original: finding,
    };
  } 
  
  if (isCmFindingV2(finding)) {
     return {
       filePath: finding.file_path,
       vulnerabilityId: finding.vuln_id,
       snippet: finding.snippet,
       original: finding,
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
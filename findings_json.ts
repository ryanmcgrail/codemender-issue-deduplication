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
  vuln_id?: string;
  vuln_type?: string;
  snippet: string;
}

interface CmFindingV3 {
  file: string;
  type?: string;
  snippet?: string;
}

function isCmFindingV2(finding: any): finding is CmFindingV2 {
  return (
    finding !== null &&
    typeof finding === "object" &&
    typeof finding.file_path === "string" &&
    typeof finding.snippet === "string"
  );
}

function isCmFindingV3(finding: any): finding is CmFindingV3 {
  return (
    finding !== null &&
    typeof finding === "object" &&
    typeof finding.file === "string" &&
    (finding.snippet === undefined || typeof finding.snippet === "string")
  );
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
      vulnerabilityId: finding.vuln_id ?? finding.vuln_type ?? "",
       snippet: finding.snippet,
       original: finding,
     };
   }

  if (isCmFindingV3(finding)) {
    return {
      filePath: finding.file,
      vulnerabilityId: finding.type ?? "",
      snippet: finding.snippet ?? "",
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
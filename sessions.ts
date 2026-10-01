import { readdir, readFile } from "node:fs/promises";

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

function parseFindingsJson(jsonString: string): Finding[] | null {
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

export interface Session {
  path: string;
  findings: Finding[];
}

const findingsJsonFiles: string[] = (
  await readdir("results", { recursive: true })
).filter((file) => file.endsWith("findings.json"));

const allSessions = (
  await Promise.all(
    findingsJsonFiles.map(
      async (path) => {
        const contents = await readFile(`results/${path}`, "utf8");
        const findings = parseFindingsJson(contents);
        if (!!findings) {
          return { path, findings };
        }
        return null;
      }
    ),
  )
)
  .filter((o) => !!o)
  .sort((a, b) => a.path.localeCompare(b.path));

export const sessionsByVersionAndRepo = new Map<string, Session[]>();
for (const session of allSessions) {
  const versionAndRepo = session.path.slice(0, session.path.indexOf("/repeat"));
  if (!sessionsByVersionAndRepo.has(versionAndRepo)) {
    sessionsByVersionAndRepo.set(versionAndRepo, []);
  }
  sessionsByVersionAndRepo.get(versionAndRepo)?.push(session);
}
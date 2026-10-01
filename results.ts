import { readdir, readFile } from "node:fs/promises";
import { Dirent } from "node:fs";

import { type Finding } from "./finding.ts";
import { type SessionSummary } from "./session_summary.ts";
import { parseFindingsJson } from "./findings_json.ts";
import { parseSessionSummaryJson } from "./session_summary_json.ts";

interface SessionFiles {
  findingsJsonFile: Dirent<string>;
  sessionSummaryJsonFile: Dirent<string>;
}

const results = new Array<SessionFiles>();

const directoryQueue = await readdir("results", { withFileTypes: true });
while (directoryQueue.length > 0) {
  const currentDirectory = directoryQueue.shift()!;
  if (!currentDirectory.isDirectory()) {
    continue;
  }

  const currentPath = `${currentDirectory.parentPath}/${currentDirectory.name}`;
  const children = await readdir(currentPath, { withFileTypes: true });

  if (currentDirectory.name.startsWith("repeat_")) {
    const findingsJsonFile = children.find((child) => child.name === "findings.json");
    const sessionSummaryJsonFile = children.find((child) => child.name === "session_summary.json");

    if (findingsJsonFile && sessionSummaryJsonFile) {
      results.push({ findingsJsonFile, sessionSummaryJsonFile });
    } else if (findingsJsonFile) {
      console.warn(`WARNING: Only found findings.json.`);
    }
    else if (sessionSummaryJsonFile) {
      console.warn(`WARNING: Only found session_summary.json.`);
    }

    continue;
  }

  directoryQueue.push(...children);
}


export interface Session {
  path: string;
  findings: Finding[];
  sessionSummary: SessionSummary;
}

const sessions = new Array<Session>();

for (const {findingsJsonFile, sessionSummaryJsonFile} of results) {
  const findingsJsonContents = await readFile(
    `${findingsJsonFile.parentPath}/${findingsJsonFile.name}`,
    "utf8",
  );
  const findings = parseFindingsJson(findingsJsonContents);

  const sessionSummaryJsonContents = await readFile(
    `${sessionSummaryJsonFile.parentPath}/${sessionSummaryJsonFile.name}`,
    "utf8",
  );
  const sessionSummary = parseSessionSummaryJson(sessionSummaryJsonContents);

  if (findings && sessionSummary) {
    sessions.push({
      path: findingsJsonFile.parentPath,
      findings,
      sessionSummary,
    });
  }
}

sessions.sort((a, b) => a.path.localeCompare(b.path));

export const sessionsByVersionAndRepo = new Map<string, Session[]>();
for (const session of sessions) {
  const versionAndRepo = session.path.slice(0, session.path.indexOf("/repeat"));
  if (!sessionsByVersionAndRepo.has(versionAndRepo)) {
    sessionsByVersionAndRepo.set(versionAndRepo, []);
  }
  sessionsByVersionAndRepo.get(versionAndRepo)?.push(session);
}
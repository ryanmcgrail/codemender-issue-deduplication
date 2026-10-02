import { readdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve, sep } from "node:path";

import { parseFindingsJson } from "./findings_json.ts";
import { parseSessionSummaryJson } from "./session_summary_json.ts";

interface RepositoryDatabase {
  findings: FindingGroup[];
}

interface FindingGroup {
  filePath: string;
  occurrences: FindingOccurrence[];
}

interface FindingOccurrence {
  filePath: string;
  snippet: string;
  vulnerabilityId: string;
}

const resultsDirectory = resolve("results");
const outputPath = resolve("findings_database.json");
const findingsFiles = (await findFindingsFiles(resultsDirectory)).sort();
const repositoryGroups = new Map<
  string,
  Map<string, Map<string, FindingGroup>>
>();
const skippedFiles: string[] = [];
let sourceFileCount = 0;
let findingCount = 0;
let filesWithoutSummary = 0;

for (const findingsFile of findingsFiles) {
  let findings;
  let rawFindings: unknown;
  try {
    const findingsJson = await readFile(findingsFile, "utf8");
    rawFindings = JSON.parse(findingsJson);
    findings = parseFindingsJson(findingsJson);
  } catch (error) {
    skippedFiles.push(`${relative(process.cwd(), findingsFile)}: ${String(error)}`);
    continue;
  }

  if (!findings) {
    if (rawFindings === null || (Array.isArray(rawFindings) && rawFindings.length === 0)) {
      sourceFileCount++;
      continue;
    }
    skippedFiles.push(`${relative(process.cwd(), findingsFile)}: no supported findings`);
    continue;
  }

  const repeatDirectory = dirname(findingsFile);
  const repository = getRepositoryName(repeatDirectory, resultsDirectory);
  const summaryPath = join(repeatDirectory, "session_summary.json");
  let workingDirectory = "";

  try {
    const summary = parseSessionSummaryJson(await readFile(summaryPath, "utf8"));
    workingDirectory = summary?.working_dir ?? "";
  } catch {
    filesWithoutSummary++;
  }

  sourceFileCount++;
  if (!repositoryGroups.has(repository)) {
    repositoryGroups.set(repository, new Map());
  }
  const groupsByPath = repositoryGroups.get(repository)!;

  for (const finding of findings) {
    const filePath = normalizeRepositoryPath(
      finding.filePath,
      workingDirectory,
      repository,
    );
    let groupsBySnippet = groupsByPath.get(filePath);
    if (!groupsBySnippet) {
      groupsBySnippet = new Map();
      groupsByPath.set(filePath, groupsBySnippet);
    }

    let group = groupsBySnippet.get(finding.snippet);
    if (!group) {
      group = {
        filePath,
        occurrences: [],
      };
      groupsBySnippet.set(finding.snippet, group);
    }

    group.occurrences.push({
      filePath: relative(process.cwd(), findingsFile).split(sep).join("/"),
      snippet: finding.snippet,
      vulnerabilityId: finding.vulnerabilityId,
    });
    findingCount++;
  }
}

const repositories: Record<string, RepositoryDatabase> = {};

for (const [repository, groupsByPath] of [...repositoryGroups.entries()].sort(
  ([left], [right]) => left.localeCompare(right),
)) {
  const findings = [...groupsByPath.values()]
    .flatMap((groupsBySnippet) => [...groupsBySnippet.values()])
    .sort((left, right) => left.filePath.localeCompare(right.filePath));
  repositories[repository] = { findings };
}

const database = {
  schemaVersion: 1,
  summary: {
    findingsFilesDiscovered: findingsFiles.length,
    findingsFilesProcessed: sourceFileCount,
    findingsFilesSkipped: skippedFiles.length,
    findingsFilesWithoutSummary: filesWithoutSummary,
    repositories: Object.keys(repositories).length,
  },
  repositories,
  skippedFiles,
};

await writeFile(outputPath, `${JSON.stringify(database, null, 2)}\n`);
console.log(`Wrote ${relative(process.cwd(), outputPath)}`);
console.log(JSON.stringify(database.summary, null, 2));
if (skippedFiles.length > 0) {
  console.warn(`Skipped ${skippedFiles.length} findings file(s):`);
  for (const skippedFile of skippedFiles) {
    console.warn(`  ${skippedFile}`);
  }
}

async function findFindingsFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const nestedResults = await Promise.all(
    entries.map(async (entry) => {
      const entryPath = join(directory, entry.name);
      if (entry.isDirectory()) {
        return findFindingsFiles(entryPath);
      }
      return entry.name === "findings.json" ? [entryPath] : [];
    }),
  );
  return nestedResults.flat();
}

function getRepositoryName(repeatDirectory: string, resultsRoot: string): string {
  let currentDirectory = repeatDirectory;
  while (currentDirectory.startsWith(`${resultsRoot}/`)) {
    if (/^repeat(?:_|-|\d)/i.test(basename(currentDirectory))) {
      return basename(dirname(currentDirectory));
    }
    currentDirectory = dirname(currentDirectory);
  }

  return basename(repeatDirectory);
}

function normalizeRepositoryPath(
  filePath: string,
  workingDirectory: string,
  repository: string,
): string {
  const normalizedFilePath = normalizePath(filePath);
  const normalizedWorkingDirectory = normalizePath(workingDirectory);

  if (
    normalizedWorkingDirectory &&
    normalizedFilePath.startsWith(`${normalizedWorkingDirectory}/`)
  ) {
    return normalizedFilePath.slice(normalizedWorkingDirectory.length + 1);
  }

  const pathParts = normalizedFilePath.split("/");
  const repositoryIndex = pathParts.findIndex(
    (part) =>
      part === repository ||
      part.startsWith(`${repository}_rep`) ||
      part.startsWith(`${repository}-rep`),
  );
  if (repositoryIndex >= 0) {
    return pathParts.slice(repositoryIndex + 1).join("/");
  }

  return normalizedFilePath;
}

function normalizePath(filePath: string): string {
  const normalized = filePath.trim().replace(/\\/g, "/");
  if (!normalized) {
    return "";
  }

  return normalized.startsWith("/")
    ? `/${normalizeSegments(normalized.split("/"))}`
    : normalizeSegments(normalized.split("/"));
}

function normalizeSegments(segments: string[]): string {
  const normalized: string[] = [];
  for (const segment of segments) {
    if (!segment || segment === ".") {
      continue;
    }
    if (
      segment === ".." &&
      normalized.length > 0 &&
      normalized[normalized.length - 1] !== ".."
    ) {
      normalized.pop();
    } else if (segment !== "..") {
      normalized.push(segment);
    } else {
      normalized.push(segment);
    }
  }
  return normalized.join("/");
}
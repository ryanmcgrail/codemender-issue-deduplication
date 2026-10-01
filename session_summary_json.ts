import { type SessionSummary } from "./session_summary.ts";

export function parseSessionSummaryJson(jsonString: string): SessionSummary | null {
  const sessionSummary = JSON.parse(jsonString) as SessionSummary;
  if (!sessionSummary) {
    return null;
  }
  
  return sessionSummary;
}
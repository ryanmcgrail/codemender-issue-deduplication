export interface Finding {
  filePath: string;
  vulnerabilityId: string;
  snippet: string;
  original?: any;
}
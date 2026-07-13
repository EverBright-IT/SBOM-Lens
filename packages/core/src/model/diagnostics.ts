export type DiagnosticSeverity = 'error' | 'warning' | 'info';

export interface Diagnostic {
  severity: DiagnosticSeverity;
  /** Stable machine-readable code, e.g. 'TV_MALFORMED_LINE'. */
  code: string;
  message: string;
  /** 1-based line number (tag-value sources). */
  line?: number;
}

export function diag(
  severity: DiagnosticSeverity,
  code: string,
  message: string,
  line?: number,
): Diagnostic {
  return line === undefined ? { severity, code, message } : { severity, code, message, line };
}

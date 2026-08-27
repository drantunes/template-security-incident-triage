import type { z } from "zod";

export type DomainErrorCode =
  | "CONFLICT"
  | "INVALID_TRANSITION"
  | "NOT_FOUND"
  | "STORAGE_UNAVAILABLE"
  | "VALIDATION_FAILED";

const publicMessages: Record<DomainErrorCode, string> = {
  CONFLICT: "The operation conflicts with the current state.",
  INVALID_TRANSITION: "The requested state transition is not allowed.",
  NOT_FOUND: "The requested resource was not found.",
  STORAGE_UNAVAILABLE: "Storage is temporarily unavailable.",
  VALIDATION_FAILED: "The request is invalid.",
};

export class DomainError extends Error {
  readonly code: DomainErrorCode;
  readonly retryable: boolean;

  constructor(code: DomainErrorCode, options: { retryable?: boolean } = {}) {
    super(publicMessages[code]);
    this.name = "DomainError";
    this.code = code;
    this.retryable = options.retryable ?? false;
  }

  toPublic(): Readonly<{
    code: DomainErrorCode;
    message: string;
    retryable: boolean;
  }> {
    return Object.freeze({
      code: this.code,
      message: publicMessages[this.code],
      retryable: this.retryable,
    });
  }
}

export function toStorageError(error: unknown): DomainError {
  if (error instanceof DomainError) return error;
  const codes = extractDriverCodes(error);
  if (
    codes.includes("SQLITE_CONSTRAINT_UNIQUE") ||
    codes.includes("SQLITE_CONSTRAINT_PRIMARYKEY")
  ) {
    return new DomainError("CONFLICT");
  }
  const retryable =
    codes.includes("SQLITE_BUSY") || codes.includes("SQLITE_LOCKED");
  return new DomainError("STORAGE_UNAVAILABLE", { retryable });
}

export function parseDomainSchema<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) throw new DomainError("VALIDATION_FAILED");
  return result.data;
}

function extractDriverCodes(error: unknown): readonly string[] {
  if (typeof error !== "object" || error === null) return [];
  const record = error as Record<string, unknown>;
  const codes: string[] = [];
  for (const key of ["code", "extendedCode"] as const) {
    const value = record[key];
    if (typeof value === "string") codes.push(value);
  }
  codes.push(...extractDriverCodes(record.cause));
  return codes;
}

import { createHmac, timingSafeEqual } from "node:crypto";

export function createCsrfToken(
  secret: string,
  input: Readonly<{ sessionId: string; tenantId: string }>,
): string {
  return createHmac("sha256", secret)
    .update(`${input.sessionId}\u0000${input.tenantId}`)
    .digest("base64url");
}

export function verifyCsrfToken(
  secret: string,
  input: Readonly<{
    sessionId: string;
    tenantId: string;
    token: string | undefined;
  }>,
): boolean {
  if (!input.token || !/^[A-Za-z0-9_-]{43}$/.test(input.token)) return false;
  const expected = createCsrfToken(secret, input);
  return timingSafeEqual(Buffer.from(expected), Buffer.from(input.token));
}

export function isSameOriginMutation(
  request: Request,
  expectedOrigin: string,
): boolean {
  return (
    request.headers.get("origin") === expectedOrigin &&
    request.headers.get("sec-fetch-site") === "same-origin"
  );
}

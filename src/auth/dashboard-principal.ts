import { z } from "zod";

import { opaqueId } from "../schemas/common.js";

export const DashboardRoleSchema = z.enum([
  "viewer",
  "soc_analyst",
  "soc_manager",
]);

export type DashboardRole = z.infer<typeof DashboardRoleSchema>;

export const DashboardPrincipalSchema = z
  .object({
    userRef: opaqueId,
    tenantId: opaqueId,
    organizationId: opaqueId,
    role: DashboardRoleSchema,
    sessionRef: opaqueId,
  })
  .strict()
  .refine((value) => value.tenantId === value.organizationId, {
    message: "The active organization must be the tenant.",
  });

export type DashboardPrincipal = z.infer<typeof DashboardPrincipalSchema>;

export type VerifiedDashboardSession = Readonly<{
  userId: string;
  sessionId: string;
  organizationId: string | undefined;
  roles: readonly string[];
}>;

export function resolveDashboardPrincipal(
  session: VerifiedDashboardSession,
): DashboardPrincipal | null {
  const roles = [...new Set(session.roles)];
  if (
    !session.organizationId ||
    roles.length !== 1 ||
    !DashboardRoleSchema.options.includes(roles[0] as DashboardRole)
  )
    return null;
  return (
    DashboardPrincipalSchema.safeParse({
      userRef: session.userId,
      tenantId: session.organizationId,
      organizationId: session.organizationId,
      role: roles[0],
      sessionRef: session.sessionId,
    }).data ?? null
  );
}

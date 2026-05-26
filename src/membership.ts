import { Octokit } from "@octokit/rest";

export async function requireOrgRole(
  token: string,
  org: string,
  role: "admin" | "member",
): Promise<Response | null> {
  const actual = await checkOrgRole(token, org);
  const ok = role === "member" ? actual !== null : actual === "admin";
  const msg = role === "admin" ? "Forbidden: org admin required" : "Forbidden: org membership required";
  return ok ? null : new Response(msg, { status: 403 });
}

export async function checkOrgRole(
  token: string,
  org: string,
): Promise<"admin" | "member" | null> {
  const octokit = new Octokit({ auth: token });
  return octokit.rest.orgs
    .getMembershipForAuthenticatedUser({ org })
    .then(({ data }) => {
      if (data.state !== "active") return null;
      return data.role === "admin" ? "admin" : "member";
    })
    .catch(() => null);
}

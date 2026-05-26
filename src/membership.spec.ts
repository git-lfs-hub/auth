import { describe, test, expect, vi } from "vitest";

vi.mock("@octokit/rest", () => ({
  Octokit: vi.fn(),
}));

import { Octokit } from "@octokit/rest";
import { checkOrgRole, requireOrgRole } from "./membership";

const MockOctokit = vi.mocked(Octokit);

function mockOctokit(impl: any) {
  MockOctokit.mockImplementationOnce(function () {
    return impl;
  } as any);
}

describe("checkOrgRole", () => {
  test("returns 'admin' for active admin membership", async () => {
    mockOctokit({
      rest: {
        orgs: {
          getMembershipForAuthenticatedUser: () =>
            Promise.resolve({ data: { state: "active", role: "admin" } }),
        },
      },
    });

    expect(await checkOrgRole("tok", "my-org")).toBe("admin");
  });

  test("returns 'member' for active member", async () => {
    mockOctokit({
      rest: {
        orgs: {
          getMembershipForAuthenticatedUser: () =>
            Promise.resolve({ data: { state: "active", role: "member" } }),
        },
      },
    });

    expect(await checkOrgRole("tok", "my-org")).toBe("member");
  });

  test("returns null for pending membership", async () => {
    mockOctokit({
      rest: {
        orgs: {
          getMembershipForAuthenticatedUser: () =>
            Promise.resolve({ data: { state: "pending", role: "member" } }),
        },
      },
    });

    expect(await checkOrgRole("tok", "my-org")).toBeNull();
  });

  test("returns null when API errors (not a member)", async () => {
    mockOctokit({
      rest: {
        orgs: {
          getMembershipForAuthenticatedUser: () =>
            Promise.reject(new Error("404")),
        },
      },
    });

    expect(await checkOrgRole("tok", "my-org")).toBeNull();
  });
});

describe("requireOrgRole", () => {
  function mockRole(role: "admin" | "member" | null) {
    mockOctokit({
      rest: {
        orgs: {
          getMembershipForAuthenticatedUser: () =>
            role === null
              ? Promise.reject(new Error("404"))
              : Promise.resolve({ data: { state: "active", role } }),
        },
      },
    });
  }

  test("admin role passes admin requirement", async () => {
    mockRole("admin");
    expect(await requireOrgRole("tok", "org", "admin")).toBeNull();
  });

  test("member role fails admin requirement", async () => {
    mockRole("member");
    const res = await requireOrgRole("tok", "org", "admin");
    expect(res?.status).toBe(403);
  });

  test("non-member fails admin requirement", async () => {
    mockRole(null);
    const res = await requireOrgRole("tok", "org", "admin");
    expect(res?.status).toBe(403);
  });

  test("admin role passes member requirement", async () => {
    mockRole("admin");
    expect(await requireOrgRole("tok", "org", "member")).toBeNull();
  });

  test("member role passes member requirement", async () => {
    mockRole("member");
    expect(await requireOrgRole("tok", "org", "member")).toBeNull();
  });

  test("non-member fails member requirement", async () => {
    mockRole(null);
    const res = await requireOrgRole("tok", "org", "member");
    expect(res?.status).toBe(403);
  });
});

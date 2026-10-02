import { createHash } from "node:crypto";
import Pino from "pino";
import supertest from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import * as TDB from "../__tests__/testDataBuilder";
import { createServer, type ServerOptions } from "../server/server";
import type { Services } from "../services";
import { browserSessionCookieName } from "./browserSessionStore";

const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const query = {
  client_id: "client",
  redirect_uri: "http://localhost:3000/callback",
  response_type: "code",
  code_challenge: createHash("sha256").update(verifier).digest("base64url"),
  code_challenge_method: "S256",
  state: "state & 日本語",
  scope: "openid",
};
const form = { ...query, username: "user", password: "Password123!" };
const logout = { client_id: "client", logout_uri: "http://localhost:3000/" };

function fixture(options: ServerOptions = {}) {
  const clock = new ClockFake(new Date());
  const user = TDB.user({
    Username: "user",
    Password: form.password,
    UserStatus: "CONFIRMED",
  });
  const pool = newMockUserPoolService({ Id: "pool" });
  pool.getUserByUsername.mockResolvedValue(user);
  pool.listUserGroupMembership.mockResolvedValue([]);
  const cognito = newMockCognitoService(pool);
  const client = TDB.appClient({
    ClientId: "client",
    UserPoolId: "pool",
    CallbackURLs: [query.redirect_uri],
    LogoutURLs: [logout.logout_uri],
  });
  cognito.getAppClient.mockResolvedValue(client);
  cognito.getUserPoolForClientId.mockResolvedValue(pool);
  cognito.getUserPool.mockResolvedValue(pool);
  const tokenGenerator = newMockTokenGenerator();
  tokenGenerator.generate.mockResolvedValue({
    AccessToken: "access",
    IdToken: "id",
    RefreshToken: "refresh",
  });
  const logs: string[] = [];
  const logger = Pino(
    { level: "debug" },
    {
      write: (chunk) => {
        logs.push(chunk);
      },
    },
  );
  const app = createServer(vi.fn(), logger, options, {
    clock,
    cognito,
    tokenGenerator,
  } as unknown as Services).application;
  const request = supertest(app);
  const login = (cookie?: string) =>
    request
      .post("/oauth2/authorize")
      .set("Cookie", cookie ?? "")
      .type("form")
      .send(form);
  const authorize = (cookie = "", extra = {}) =>
    request
      .get("/oauth2/authorize")
      .set("Cookie", cookie)
      .query({ ...query, prompt: "none", ...extra });
  return {
    clock,
    user,
    pool,
    cognito,
    client,
    request,
    login,
    authorize,
    logs,
  };
}

describe("OAuth browser sessions", () => {
  let f: ReturnType<typeof fixture>;
  beforeEach(() => {
    f = fixture();
  });
  const cookieOf = (res: supertest.Response) =>
    res.header["set-cookie"][0].split(";")[0];

  it("returns login_required and the original state without interaction when there is no session", async () => {
    const res = await f.authorize();
    expect(res.status).toBe(302);
    const location = new URL(res.header.location);
    expect(location.origin + location.pathname).toBe(query.redirect_uri);
    expect(location.searchParams.get("error")).toBe("login_required");
    expect(location.searchParams.get("state")).toBe(query.state);
    expect(res.header["set-cookie"]).toBeUndefined();
  });

  it("sets a host-only, HttpOnly, Lax cookie then reuses it without renewal, issuing distinct single-use PKCE codes", async () => {
    const login = await f.login();
    expect(login.status).toBe(302);
    const cookie = cookieOf(login);
    expect(cookie.split("=")[1]).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(login.header["set-cookie"][0]).toMatch(
      /Path=\/; Expires=.*; HttpOnly; SameSite=Lax/,
    );
    expect(login.header["set-cookie"][0]).not.toMatch(/Domain=|Secure/);
    expect(login.header["cache-control"]).toBe("no-store");
    const seen = new Set([
      new URL(login.header.location).searchParams.get("code"),
    ]);
    for (const prompt of ["none", "", "none"]) {
      const res = await f.authorize(cookie, { prompt });
      expect(res.status).toBe(302);
      expect(res.header["set-cookie"]).toBeUndefined();
      const code = new URL(res.header.location).searchParams.get("code");
      expect(code).toBeTruthy();
      expect(seen.has(code)).toBe(false);
      seen.add(code);
      const tokenBody = {
        grant_type: "authorization_code",
        code,
        client_id: query.client_id,
        redirect_uri: query.redirect_uri,
        code_verifier: verifier,
      };
      const first = await f.request
        .post("/oauth2/token")
        .type("form")
        .send(tokenBody);
      expect(first.status).toBe(200);
      const replay = await f.request
        .post("/oauth2/token")
        .type("form")
        .send(tokenBody);
      expect(replay.body.error).toBe("invalid_grant");
    }
    const res = await f.authorize(cookie);
    const invalid = await f.request
      .post("/oauth2/token")
      .type("form")
      .send({
        grant_type: "authorization_code",
        code: new URL(res.header.location).searchParams.get("code"),
        client_id: query.client_id,
        redirect_uri: query.redirect_uri,
        code_verifier: "wrong",
      });
    expect(invalid.body.error).toBe("invalid_grant");
    expect(f.logs.join("")).not.toContain(cookie.split("=")[1]);
  });

  it("does not renew at reuse and rejects the exact one-hour boundary", async () => {
    const cookie = cookieOf(await f.login());
    f.clock.advanceBy(3_599_999);
    expect(
      new URL((await f.authorize(cookie)).header.location).searchParams.has(
        "code",
      ),
    ).toBe(true);
    f.clock.advanceBy(1);
    expect(
      new URL((await f.authorize(cookie)).header.location).searchParams.get(
        "error",
      ),
    ).toBe("login_required");
    expect((await f.authorize(cookie, { prompt: "" })).text).toContain("<form");
  });

  it("forces login and rotates the old session only after successful interactive authentication", async () => {
    const cookie = cookieOf(await f.login());
    expect((await f.authorize(cookie, { prompt: "login" })).text).toContain(
      "<form",
    );
    const bad = await f.request
      .post("/oauth2/authorize")
      .type("form")
      .send({ ...form, password: "wrong" });
    expect(bad.header["set-cookie"]).toBeUndefined();
    const renewed = await f.login(cookie);
    expect(cookieOf(renewed)).not.toBe(cookie);
    expect(
      new URL((await f.authorize(cookie)).header.location).searchParams.get(
        "error",
      ),
    ).toBe("login_required");
    expect(
      new URL(
        (await f.authorize(cookieOf(renewed))).header.location,
      ).searchParams.has("code"),
    ).toBe(true);
  });

  it("shares a session across clients of the same pool, never across pools even with a renamed cookie", async () => {
    const cookie = cookieOf(await f.login());
    f.cognito.getAppClient.mockResolvedValue({
      ...f.client,
      ClientId: "second",
    });
    expect(
      new URL(
        (await f.authorize(cookie, { client_id: "second" })).header.location,
      ).searchParams.has("code"),
    ).toBe(true);
    const other = newMockUserPoolService({ Id: "other" });
    other.getUserByUsername.mockResolvedValue(f.user);
    f.cognito.getUserPoolForClientId.mockResolvedValue(other);
    const renamed = `${browserSessionCookieName("other")}=${cookie.split("=")[1]}`;
    expect(
      new URL((await f.authorize(renamed)).header.location).searchParams.get(
        "error",
      ),
    ).toBe("login_required");
  });

  it("rejects tampered and duplicate cookies, disabled/deleted users and recreated usernames", async () => {
    const cookie = cookieOf(await f.login());
    for (const value of [
      `${cookie}x`,
      `${cookie}; ${cookie}`,
      `${cookie.split("=")[0]}=${"A".repeat(43)}`,
    ]) {
      expect(
        new URL((await f.authorize(value)).header.location).searchParams.get(
          "error",
        ),
      ).toBe("login_required");
    }
    for (const user of [
      null,
      { ...f.user, Enabled: false },
      TDB.user({ Username: f.user.Username }),
    ]) {
      f.pool.getUserByUsername.mockResolvedValue(user);
      expect(
        new URL((await f.authorize(cookie)).header.location).searchParams.get(
          "error",
        ),
      ).toBe("login_required");
    }
  });

  it("validates callbacks and prompts before redirecting or reusing sessions", async () => {
    const cookie = cookieOf(await f.login());
    for (const extra of [
      { redirect_uri: "https://example.invalid/" },
      { prompt: "none login" },
    ]) {
      const res = await f.authorize(cookie, extra);
      expect(res.status).toBe(400);
      expect(res.header.location).toBeUndefined();
    }
  });

  it("validates logout destinations before revocation, then clears only the current browser session", async () => {
    const cookie = cookieOf(await f.login());
    const otherBrowser = cookieOf(await f.login());
    for (const params of [
      { ...logout, logout_uri: "https://example.invalid/" },
      { client_id: "client" },
    ]) {
      expect(
        (await f.request.get("/logout").set("Cookie", cookie).query(params))
          .status,
      ).toBe(400);
    }
    expect(
      new URL((await f.authorize(cookie)).header.location).searchParams.has(
        "code",
      ),
    ).toBe(true);
    const res = await f.request
      .get("/logout")
      .set("Cookie", cookie)
      .query(logout);
    expect(res.status).toBe(302);
    expect(res.header.location).toBe(logout.logout_uri);
    expect(res.header["set-cookie"][0]).toContain("Expires=Thu, 01 Jan 1970");
    expect(
      new URL((await f.authorize(cookie)).header.location).searchParams.get(
        "error",
      ),
    ).toBe("login_required");
    expect(
      new URL(
        (await f.authorize(otherBrowser)).header.location,
      ).searchParams.has("code"),
    ).toBe(true);
    f.cognito.getAppClient.mockResolvedValue({ ...f.client, LogoutURLs: [] });
    expect((await f.request.get("/logout").query(logout)).status).toBe(400);
  });

  it.each([false, true])(
    "trusts forwarded HTTPS only when loopback proxy trust is explicitly enabled (%s)",
    async (trusted) => {
      const server = fixture(trusted ? { trustProxy: "loopback" } : {});
      const login = await server.request
        .post("/oauth2/authorize")
        .set("X-Forwarded-Proto", "https")
        .type("form")
        .send(form);
      expect(login.header["set-cookie"][0].includes("; Secure")).toBe(trusted);
    },
  );
});

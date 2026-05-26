import { SignJWT, jwtVerify } from "jose";
import { keyBytes } from "./_key";
import { encryptSession, SESSION_TTL, type SessionPayload } from "./session";

export interface StatePayload {
  redirect_uri: string;
  client_state: string;
  scopes: string;
}

export async function signState(
  payload: StatePayload,
  secret: string,
  ttlSeconds = 600,
): Promise<string> {
  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime(Math.floor(Date.now() / 1000) + ttlSeconds)
    .sign(keyBytes(secret));
}

export async function verifyState(
  token: string,
  secret: string,
): Promise<StatePayload | null> {
  try {
    const { payload } = await jwtVerify(token, keyBytes(secret));
    return {
      redirect_uri: payload.redirect_uri as string,
      client_state: payload.client_state as string,
      scopes: payload.scopes as string,
    };
  } catch {
    return null;
  }
}

export function buildAuthorizeUrl(
  clientId: string,
  redirectUri: string,
  state: string,
  opts?: { scope?: string; login?: string },
): string {
  const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("state", state);
  if (opts?.scope) url.searchParams.set("scope", opts.scope);
  if (opts?.login) url.searchParams.set("login", opts.login);
  return url.toString();
}

export function buildOAuthErrorRedirectUrl(error: string, statePayload: StatePayload): string {
  const url = new URL(statePayload.redirect_uri);
  url.searchParams.set("error", error);
  if (statePayload.client_state) url.searchParams.set("state", statePayload.client_state);
  return url.toString();
}

export type OAuthCallbackResult =
  | { ok: true; encrypted: string; tokenPayload: SessionPayload; statePayload: StatePayload }
  | { ok: false; error: string; statePayload?: StatePayload };

export async function processOAuthCallback(opts: {
  code: string;
  state: string;
  secret: string;
  clientId: string;
  clientSecret: string;
  callbackUrl: string;
}): Promise<OAuthCallbackResult> {
  const statePayload = await verifyState(opts.state, opts.secret);
  if (!statePayload) return { ok: false, error: "invalid_state" };

  const data = await exchangeCode(opts.clientId, opts.clientSecret, opts.code, opts.callbackUrl);
  if (data.error || !data.access_token) return { ok: false, error: data.error ?? "no_token", statePayload };

  const tokenPayload: SessionPayload = { token: data.access_token };
  if (typeof data.refresh_token === "string") tokenPayload.refresh_token = data.refresh_token;

  const encrypted = await encryptSession(tokenPayload, opts.secret, SESSION_TTL);
  return { ok: true, encrypted, tokenPayload, statePayload };
}

export async function exchangeCode(
  clientId: string,
  clientSecret: string,
  code: string,
  redirectUri: string,
): Promise<Record<string, string>> {
  const params = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    code,
    redirect_uri: redirectUri,
  });
  const res = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: params,
  });
  return res.json() as Promise<Record<string, string>>;
}

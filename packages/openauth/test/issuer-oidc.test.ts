import {
  afterEach,
  beforeEach,
  describe,
  expect,
  setSystemTime,
  test,
} from "bun:test";
import { decodeJwt } from "jose";
import { object, string } from "valibot";
import { createClient } from "../src/client.js";
import { issuer } from "../src/issuer.js";
import type { Provider } from "../src/provider/provider.js";
import { MemoryStorage } from "../src/storage/memory.js";
import { createSubjects } from "../src/subject.js";

const subjects = createSubjects({
  user: object({
    userID: string(),
  }),
});

const storage = MemoryStorage();
const issuerConfig = {
  storage,
  subjects,
  allow: async () => true,
  ttl: {
    access: 60,
    refresh: 6000,
    refreshReuse: 60,
    refreshRetention: 6000,
  },
  providers: {
    dummy: {
      type: "dummy",
      init(route, ctx) {
        route.get("/authorize", async (c) => {
          return ctx.success(c, {
            email: "foo@bar.com",
          });
        });
      },
      client: async ({ clientID, clientSecret }) => {
        if (clientID !== "myuser" && clientSecret !== "mypass") {
          throw new Error("Wrong credentials");
        }
        return {
          email: "foo@bar.com",
        };
      },
    } satisfies Provider<{ email: string }>,
  },
  success: async (ctx, value) => {
    if (value.provider === "dummy") {
      return ctx.subject("user", {
        userID: "123",
      });
    }
    throw new Error("Invalid provider: " + value.provider);
  },
};
const auth = issuer(issuerConfig);

const expectNonEmptyString = expect.stringMatching(/.+/);

beforeEach(async () => {
  setSystemTime(new Date("1/1/2024"));
});

afterEach(() => {
  setSystemTime();
});

describe("OpenID Connect Discovery", () => {
  test("GET /.well-known/openid-configuration returns correct JSON", async () => {
    const response = await auth.request(
      "https://auth.example.com/.well-known/openid-configuration",
    );
    expect(response.status).toBe(200);

    const config = await response.json();
    expect(config).toMatchObject({
      issuer: "https://auth.example.com",
      authorization_endpoint: "https://auth.example.com/authorize",
      token_endpoint: "https://auth.example.com/token",
      jwks_uri: "https://auth.example.com/.well-known/jwks.json",
      response_types_supported: ["code", "token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["ES256"],
      token_endpoint_auth_methods_supported: [
        "client_secret_basic",
        "client_secret_post",
      ],
      scopes_supported: ["openid", "offline_access"],
      claims_supported: ["sub", "iss", "aud", "exp", "iat"],
      registration_endpoint: "https://auth.example.com/register",
      grant_types_supported: ["authorization_code", "refresh_token"],
      userinfo_endpoint: "https://auth.example.com/userinfo",
    });
  });
});

describe("Dynamic Client Registration", () => {
  test("POST /register returns client credentials", async () => {
    const body = {
      client_name: "Test Client",
      redirect_uris: ["https://client.example.com/callback"],
      scope: "openid offline_access",
      grant_types: ["authorization_code", "refresh_token"],
    };

    const response = await auth.request("https://auth.example.com/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    expect(response.status).toBe(200);
    const json = await response.json();

    // Verify client was stored
    const stored = await storage.get(["oauth:client", json.client_id]);
    expect(stored).toBeDefined();
    if (!stored) throw new Error("Client not stored");
    expect(stored.client_secret).not.toEqual(json.client_secret); // Should be hashed

    expect(json).toMatchObject({
      client_id: expectNonEmptyString,
      client_secret: expectNonEmptyString,
      redirect_uris: body.redirect_uris,
      scope: body.scope,
      grant_types: body.grant_types,
      token_endpoint_auth_method: "client_secret_post",
      created_at: expect.any(Number),
    });
  });

  test("POST /register requires redirect_uris", async () => {
    const body = {
      client_name: "Test Client",
      scope: "openid offline_access",
    };

    const response = await auth.request("https://auth.example.com/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    expect(response.status).toBe(400);
    const json = await response.json();
    expect(json.error).toBe("invalid_request");
  });
});

describe("OIDC Authorization Code Flow", () => {
  test("code flow with scope=openid returns id_token", async () => {
    // First register a client
    const registerResponse = await auth.request(
      "https://auth.example.com/register",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          client_name: "Test OIDC Client",
          redirect_uris: ["https://client.example.com/callback"],
          scope: "openid offline_access",
          grant_types: ["authorization_code", "refresh_token"],
        }),
      },
    );
    const clientCreds = await registerResponse.json();

    const client = createClient({
      issuer: "https://auth.example.com",
      clientID: clientCreds.client_id,
      fetch: (a, b) => Promise.resolve(auth.request(a, b)),
    });

    // Start auth flow with scope=openid
    const { challenge, url: baseUrl } = await client.authorize(
      "https://client.example.com/callback",
      "code",
      {
        pkce: true,
      },
    );

    // Add scope parameter to URL
    const url = new URL(baseUrl);
    url.searchParams.set("scope", "openid");

    let response = await auth.request(url.toString());
    expect(response.status).toBe(302);
    const setCookieHeader = response.headers.get("set-cookie")!;
    const [cookieValue] = setCookieHeader.split(";");
    response = await auth.request(response.headers.get("location")!, {
      headers: {
        cookie: cookieValue,
      },
    });
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location")!);
    const code = location.searchParams.get("code");
    expect(code).not.toBeNull();

    // Exchange code for tokens
    const exchangeResponse = await auth.request(
      "https://auth.example.com/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code!,
          redirect_uri: "https://client.example.com/callback",
          client_id: clientCreds.client_id,
          client_secret: clientCreds.client_secret,
          code_verifier: challenge.verifier,
        } as Record<string, string>).toString(),
      },
    );

    expect(exchangeResponse.status).toBe(200);
    const tokens = await exchangeResponse.json();

    // Verify id_token claims
    const idToken = decodeJwt(tokens.id_token);
    expect(idToken).toMatchObject({
      iss: "https://auth.example.com",
      sub: expect.any(String),
      aud: clientCreds.client_id,
      exp: expect.any(Number),
      iat: expect.any(Number),
    });

    expect(tokens).toMatchObject({
      access_token: expectNonEmptyString,
      refresh_token: expectNonEmptyString,
      id_token: expectNonEmptyString,
      token_type: "Bearer",
      expires_in: expect.any(Number),
    });
  });
});

describe("UserInfo Endpoint", () => {
  test("GET /userinfo returns user claims with valid access token", async () => {
    // First register a client
    const registerResponse = await auth.request(
      "https://auth.example.com/register",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          client_name: "Test OIDC Client",
          redirect_uris: ["https://client.example.com/callback"],
          scope: "openid",
          grant_types: ["authorization_code"],
        }),
      },
    );
    const clientCreds = await registerResponse.json();

    // Start auth flow
    const response = await auth.request(
      "https://auth.example.com/authorize?" +
        new URLSearchParams({
          response_type: "code",
          client_id: clientCreds.client_id,
          redirect_uri: "https://client.example.com/callback",
          provider: "dummy",
          scope: "openid",
        }).toString(),
    );

    expect(response.status).toBe(302);
    const setCookieHeader = response.headers.get("set-cookie")!;
    const [cookieValue] = setCookieHeader.split(";");

    // Follow redirect to provider
    const providerResponse = await auth.request(
      response.headers.get("location")!,
      {
        headers: {
          cookie: cookieValue,
        },
      },
    );
    expect(providerResponse.status).toBe(302);
    const location = new URL(providerResponse.headers.get("location")!);
    const code = location.searchParams.get("code");
    expect(code).not.toBeNull();

    // Exchange code for tokens
    const tokenResponse = await auth.request("https://auth.example.com/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code!,
        redirect_uri: "https://client.example.com/callback",
        client_id: clientCreds.client_id,
        client_secret: clientCreds.client_secret,
      }).toString(),
    });

    const tokens = await tokenResponse.json();
    expect(tokenResponse.status).toBe(200);

    // Call userinfo endpoint
    const userinfoResponse = await auth.request(
      "https://auth.example.com/userinfo",
      {
        headers: {
          Authorization: `Bearer ${tokens.access_token}`,
        },
      },
    );

    const userinfo = await userinfoResponse.json();
    expect(userinfoResponse.status).toBe(200);
    expect(userinfo).toMatchObject({
      sub: expect.any(String),
      userID: "123", // From our test subject
    });
  });

  test("GET /userinfo fails with invalid token", async () => {
    const response = await auth.request("https://auth.example.com/userinfo", {
      headers: {
        Authorization: "Bearer invalid-token",
      },
    });

    expect(response.status).toBe(401);
    const error = await response.json();
    expect(error.error).toBe("invalid_token");
  });
});

import type { Context } from "hono";
import { handle as awsHandle } from "hono/aws-lambda";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { cors } from "hono/cors";
import { Hono } from "hono/tiny";
import { CompactEncrypt, SignJWT, compactDecrypt, jwtVerify } from "jose";
import { ScryptHasher } from "./provider/password.js";
/**
 * The `issuer` create an OpentAuth server, a [Hono](https://hono.dev) app that's
 * designed to run anywhere.
 *
 * The `issuer` function requires a few things:
 *
 * ```ts title="issuer.ts"
 * import { issuer } from "@openauthjs/openauth"
 *
 * const app = issuer({
 *   providers: { ... },
 *   storage,
 *   subjects,
 *   success: async (ctx, value) => { ... }
 * })
 * ```
 *
 * #### Add providers
 *
 * You start by specifying the auth providers you are going to use. Let's say you want your users
 * to be able to authenticate with GitHub and with their email and password.
 *
 * ```ts title="issuer.ts"
 * import { GithubProvider } from "@openauthjs/openauth/provider/github"
 * import { PasswordProvider } from "@openauthjs/openauth/provider/password"
 *
 * const app = issuer({
 *   providers: {
 *     github: GithubAdapter({
 *       // ...
 *     }),
 *     password: PasswordProvider({
 *       // ...
 *     }),
 *   },
 * })
 * ```
 *
 * #### Handle success
 *
 * The `success` callback receives the payload when a user completes a provider's auth flow.
 *
 * ```ts title="issuer.ts"
 * const app = issuer({
 *   providers: { ... },
 *   subjects,
 *   async success(ctx, value) {
 *     let userID
 *     if (value.provider === "password") {
 *       console.log(value.email)
 *       userID = ... // lookup user or create them
 *     }
 *     if (value.provider === "github") {
 *       console.log(value.tokenset.access)
 *       userID = ... // lookup user or create them
 *     }
 *     return ctx.subject("user", {
 *       userID
 *     })
 *   }
 * })
 * ```
 *
 * Once complete, the `issuer` issues the access tokens that a client can use. The `ctx.subject`
 * call is what is placed in the access token as a JWT.
 *
 * #### Define subjects
 *
 * You define the shape of these in the `subjects` field.
 *
 * ```ts title="subjects.ts"
 * import { object, string } from "valibot"
 * import { createSubjects } from "@openauthjs/openauth/subject"
 *
 * const subjects = createSubjects({
 *   user: object({
 *     userID: string()
 *   })
 * })
 * ```
 *
 * It's good to place this in a separate file since this'll be used in your client apps as well.
 *
 * ```ts title="issuer.ts"
 * import { subjects } from "./subjects.js"
 *
 * const app = issuer({
 *   providers: { ... },
 *   subjects,
 *   // ...
 * })
 * ```
 *
 * #### Deploy
 *
 * Since `issuer` is a Hono app, you can deploy it anywhere Hono supports.
 *
 * <Tabs>
 *   <TabItem label="Node">
 *   ```ts title="issuer.ts"
 *   import { serve } from "@hono/node-server"
 *
 *   serve(app)
 *   ```
 *   </TabItem>
 *   <TabItem label="Lambda">
 *   ```ts title="issuer.ts"
 *   import { handle } from "hono/aws-lambda"
 *
 *   export const handler = handle(app)
 *   ```
 *   </TabItem>
 *   <TabItem label="Bun">
 *   ```ts title="issuer.ts"
 *   export default app
 *   ```
 *   </TabItem>
 *   <TabItem label="Workers">
 *   ```ts title="issuer.ts"
 *   export default app
 *   ```
 *   </TabItem>
 * </Tabs>
 *
 * @packageDocumentation
 */
import type { Provider, ProviderOptions } from "./provider/provider.js";
import type { SubjectPayload, SubjectSchema } from "./subject.js";

/**
 * Sets the subject payload in the JWT token and returns the response.
 *
 * ```ts
 * ctx.subject("user", {
 *   userID
 * })
 * ```
 */
export interface OnSuccessResponder<
  T extends { type: string; properties: any },
> {
  /**
   * The `type` is the type of the subject, that was defined in the `subjects` field.
   *
   * The `properties` are the properties of the subject. This is the shape of the subject that
   * you defined in the `subjects` field.
   */
  subject<Type extends T["type"]>(
    type: Type,
    properties: Extract<T, { type: Type }>["properties"],
    opts?: {
      ttl?: {
        access?: number;
        refresh?: number;
      };
      subject?: string;
    },
  ): Promise<Response>;
}

/**
 * @internal
 */
export interface AuthorizationState {
  redirect_uri: string;
  response_type: string;
  state: string;
  client_id: string;
  audience?: string;
  scope?: string;
  pkce?: {
    challenge: string;
    method: "S256";
  };
}

/**
 * @internal
 */
export type Prettify<T> = {
  [K in keyof T]: T[K];
} & {};

import type { OidcClient } from "./client.js";
import {
  MissingParameterError,
  OauthError,
  UnauthorizedClientError,
  UnknownStateError,
} from "./error.js";
import { encryptionKeys, legacySigningKeys, signingKeys } from "./keys.js";
import { validatePKCE } from "./pkce.js";
import { DynamoStorage } from "./storage/dynamo.js";
import { MemoryStorage } from "./storage/memory.js";
import { Storage, type StorageAdapter } from "./storage/storage.js";
import { Select } from "./ui/select.js";
import { setTheme, type Theme } from "./ui/theme.js";
import { isDomainMatch } from "./util.js";

/** @internal */
export const aws = awsHandle;

export interface IssuerInput<
  Providers extends Record<string, Provider<any>>,
  Subjects extends SubjectSchema,
  Result = {
    [key in keyof Providers]: Prettify<
      {
        provider: key;
      } & (Providers[key] extends Provider<infer T> ? T : {})
    >;
  }[keyof Providers],
> {
  /**
   * If using OIDC, specify a rootClientSecret which is the client secret required to call `POST /client`.
   */
  oidc?: {
    rootClientSecret: string;
  };
  /**
   * The shape of the subjects that you want to return.
   *
   * @example
   *
   * ```ts title="issuer.ts"
   * import { object, string } from "valibot"
   * import { createSubjects } from "@openauthjs/openauth/subject"
   *
   * issuer({
   *   subjects: createSubjects({
   *     user: object({
   *       userID: string()
   *     })
   *   })
   *   // ...
   * })
   * ```
   */
  subjects: Subjects;
  /**
   * The storage adapter that you want to use.
   *
   * @example
   * ```ts title="issuer.ts"
   * import { DynamoStorage } from "@openauthjs/openauth/storage/dynamo"
   *
   * issuer({
   *   storage: DynamoStorage()
   *   // ...
   * })
   * ```
   */
  storage?: StorageAdapter;
  /**
   * The providers that you want your OpenAuth server to support.
   *
   * @example
   *
   * ```ts title="issuer.ts"
   * import { GithubProvider } from "@openauthjs/openauth/provider/github"
   *
   * issuer({
   *   providers: {
   *     github: GithubProvider()
   *   }
   * })
   * ```
   *
   * The key is just a string that you can use to identify the provider. It's passed back to
   * the `success` callback.
   *
   * You can also specify multiple providers.
   *
   * ```ts
   * {
   *   providers: {
   *     github: GithubProvider(),
   *     google: GoogleProvider()
   *   }
   * }
   * ```
   */
  providers: Providers;
  /**
   * The theme you want to use for the UI.
   *
   * This includes the UI the user sees when selecting a provider. And the `PasswordUI` and
   * `CodeUI` that are used by the `PasswordProvider` and `CodeProvider`.
   *
   * @example
   * ```ts title="issuer.ts"
   * import { THEME_SST } from "@openauthjs/openauth/ui/theme"
   *
   * issuer({
   *   theme: THEME_SST
   *   // ...
   * })
   * ```
   *
   * Or define your own.
   *
   * ```ts title="issuer.ts"
   * import type { Theme } from "@openauthjs/openauth/ui/theme"
   *
   * const MY_THEME: Theme = {
   *   // ...
   * }
   *
   * issuer({
   *   theme: MY_THEME
   *   // ...
   * })
   * ```
   */
  theme?: Theme;
  /**
   * Set the TTL, in seconds, for access and refresh tokens.
   *
   * @example
   * ```ts
   * {
   *   ttl: {
   *     access: 60 * 60 * 24 * 30,
   *     refresh: 60 * 60 * 24 * 365
   *   }
   * }
   * ```
   */
  ttl?: {
    /**
     * Interval in seconds where the access token is valid.
     * @default 30d
     */
    access?: number;
    /**
     * Interval in seconds where the refresh token is valid.
     * @default 1y
     */
    refresh?: number;
    /**
     * Interval in seconds where refresh token reuse is allowed. Helps mitigrate concurrency issues.
     * @default 60s
     */
    reuse?: number;
    /**
     * Interval in seconds to retain refresh tokens for reuse detection.
     * @default 0s
     */
    retention?: number;
  };
  /**
   * Optionally, configure the UI that's displayed when the user visits the root URL of the
   * of the OpenAuth server.
   *
   * ```ts title="issuer.ts"
   * import { Select } from "@openauthjs/openauth/ui/select"
   *
   * issuer({
   *   select: Select({
   *     providers: {
   *       github: { hide: true },
   *       google: { display: "Google" }
   *     }
   *   })
   *   // ...
   * })
   * ```
   *
   * @default Select()
   */
  select?(providers: Record<string, string>, req: Request): Promise<Response>;
  /**
   * @internal
   */
  start?(req: Request): Promise<void>;
  /**
   * The success callback that's called when the user completes the flow.
   *
   * This is called after the user has been redirected back to your app after the OAuth flow.
   *
   * @example
   * ```ts
   * {
   *   success: async (ctx, value) => {
   *     let userID
   *     if (value.provider === "password") {
   *       console.log(value.email)
   *       userID = ... // lookup user or create them
   *     }
   *     if (value.provider === "github") {
   *       console.log(value.tokenset.access)
   *       userID = ... // lookup user or create them
   *     }
   *     return ctx.subject("user", {
   *       userID
   *     })
   *   },
   *   // ...
   * }
   * ```
   */
  success(
    response: OnSuccessResponder<SubjectPayload<Subjects>>,
    input: Result & {
      // TODO(sam): feels hacky to just inject this here
      authorization: AuthorizationState;
    },
    req: Request,
  ): Promise<Response>;
  /**
   * @internal
   */
  error?(error: UnknownStateError, req: Request): Promise<Response>;
  /**
   * Override the logic for whether a client request is allowed to call the issuer.
   *
   * By default, it uses the following:
   *
   * - Allow if the `redirectURI` is localhost.
   * - Compare `redirectURI` to the request's hostname or the `x-forwarded-host` header. If they
   *   are from the same sub-domain level, then allow.
   *
   * @example
   * ```ts
   * {
   *   allow: async (input, req) => {
   *     // Allow all clients
   *     return true
   *   }
   * }
   * ```
   */
  allow?(
    input: {
      clientID: string;
      redirectURI: string;
      audience?: string;
    },
    req: Request,
  ): Promise<boolean>;
}

/**
 * Create an OpenAuth server, a Hono app.
 */
export function issuer<
  Providers extends Record<string, Provider<any>>,
  Subjects extends SubjectSchema,
  Result = {
    [key in keyof Providers]: Prettify<
      {
        provider: key;
      } & (Providers[key] extends Provider<infer T> ? T : {})
    >;
  }[keyof Providers],
>(input: IssuerInput<Providers, Subjects, Result>) {
  const error =
    input.error ??
    ((err) =>
      new Response(err.message, {
        status: 400,
        headers: {
          "Content-Type": "text/plain",
        },
      }));
  const ttlAccess = input.ttl?.access ?? 60 * 60 * 24 * 30;
  const ttlRefresh = input.ttl?.refresh ?? 60 * 60 * 24 * 365;
  const ttlRefreshReuse = input.ttl?.reuse ?? 60;
  const ttlRefreshRetention = input.ttl?.retention ?? 0;
  if (input.theme) {
    setTheme(input.theme);
  }

  // Initialize a single ScryptHasher instance for all client secret hashing
  const hasher = ScryptHasher();

  const select = input.select ?? Select();
  const allow =
    input.allow ??
    (async (input, req) => {
      const redir = new URL(input.redirectURI).hostname;
      if (redir === "localhost" || redir === "127.0.0.1") {
        return true;
      }
      const forwarded = req.headers.get("x-forwarded-host");
      const host = forwarded
        ? new URL(`https://` + forwarded).hostname
        : new URL(req.url).hostname;

      return isDomainMatch(redir, host);
    });

  let storage = input.storage!;
  if (process.env.OPENAUTH_STORAGE) {
    const parsed = JSON.parse(process.env.OPENAUTH_STORAGE);
    if (parsed.type === "dynamo") storage = DynamoStorage(parsed.options);
    if (parsed.type === "memory") storage = MemoryStorage();
    if (parsed.type === "cloudflare")
      throw new Error(
        "Cloudflare storage cannot be configured through env because it requires bindings.",
      );
  }
  if (!storage)
    throw new Error(
      "Store is not configured. Either set the `storage` option or set `OPENAUTH_STORAGE` environment variable.",
    );
  const allSigning = Promise.all([
    signingKeys(storage),
    legacySigningKeys(storage),
  ]).then(([a, b]) => [...a, ...b]);
  const allEncryption = encryptionKeys(storage);
  const signingKey = allSigning.then((all) => all[0]);
  const encryptionKey = allEncryption.then((all) => all[0]);

  const auth: Omit<ProviderOptions<any>, "name"> = {
    async success(ctx: Context, properties: any, successOpts) {
      const authorization = await getAuthorization(ctx);
      return await input.success(
        {
          async subject(type, properties, subjectOpts) {
            const subject = subjectOpts?.subject
              ? subjectOpts.subject
              : await resolveSubject(type, properties);
            await successOpts?.invalidate?.(
              await resolveSubject(type, properties),
            );
            if (authorization.response_type === "token") {
              const location = new URL(authorization.redirect_uri);
              const tokens = await generateTokens(
                ctx,
                {
                  subject,
                  type: type as string,
                  properties,
                  clientID: authorization.client_id,
                  ttl: {
                    access: subjectOpts?.ttl?.access ?? ttlAccess,
                    refresh: subjectOpts?.ttl?.refresh ?? ttlRefresh,
                  },
                },
                {
                  // TODO(sam): should we generate an ID token here?
                  // generateIDToken: ??
                },
              );
              location.hash = new URLSearchParams({
                access_token: tokens.access,
                refresh_token: tokens.refresh,
                state: authorization.state || "",
              }).toString();
              await auth.unset(ctx, "authorization");
              return ctx.redirect(location.toString(), 302);
            }

            if (authorization.response_type === "code") {
              const code = crypto.randomUUID();
              await Storage.set(
                storage,
                ["oauth:code", code],
                {
                  type,
                  properties,
                  subject,
                  redirectURI: authorization.redirect_uri,
                  clientID: authorization.client_id,
                  pkce: authorization.pkce,
                  scope: authorization.scope,
                  ttl: {
                    access: subjectOpts?.ttl?.access ?? ttlAccess,
                    refresh: subjectOpts?.ttl?.refresh ?? ttlRefresh,
                  },
                },
                60, // Store code for 1 minute
              );
              const location = new URL(authorization.redirect_uri);
              location.searchParams.set("code", code);
              location.searchParams.set("state", authorization.state || "");
              await auth.unset(ctx, "authorization");
              return ctx.redirect(location.toString(), 302);
            }
            throw new OauthError(
              "invalid_request",
              `Unsupported response_type: ${authorization.response_type}`,
            );
          },
        },
        {
          provider: ctx.get("provider"),
          ...properties,
          authorization,
        },
        ctx.req.raw,
      );
    },
    forward(ctx, response) {
      return ctx.newResponse(
        response.body,
        response.status as any,
        Object.fromEntries(response.headers.entries()),
      );
    },
    async set(ctx, key, maxAge, value) {
      setCookie(ctx, key, await encrypt(value), {
        maxAge,
        httpOnly: true,
        ...(ctx.req.url.startsWith("https://")
          ? { secure: true, sameSite: "None" }
          : {}),
      });
    },
    async get(ctx: Context, key: string) {
      const raw = getCookie(ctx, key);
      if (!raw) return;
      return decrypt(raw).catch((ex) => {
        console.error("failed to decrypt", key, ex);
      });
    },
    async unset(ctx: Context, key: string) {
      deleteCookie(ctx, key);
    },
    async invalidate(subject: string) {
      // Resolve the scan in case modifications interfere with iteration
      const keys = await Array.fromAsync(
        Storage.scan(this.storage, ["oauth:refresh", subject]),
      );
      for (const [key] of keys) {
        await Storage.remove(this.storage, key);
      }
    },
    storage,
  };

  async function getAuthorization(ctx: Context) {
    const match =
      (await auth.get(ctx, "authorization")) || ctx.get("authorization");
    if (!match) throw new UnknownStateError();
    return match as AuthorizationState;
  }

  async function encrypt(value: any) {
    return await new CompactEncrypt(
      new TextEncoder().encode(JSON.stringify(value)),
    )
      .setProtectedHeader({ alg: "RSA-OAEP-512", enc: "A256GCM" })
      .encrypt(await encryptionKey.then((k) => k.public));
  }

  async function resolveSubject(type: string, properties: any) {
    const jsonString = JSON.stringify(properties);
    const encoder = new TextEncoder();
    const data = encoder.encode(jsonString);
    const hashBuffer = await crypto.subtle.digest("SHA-1", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    return `${type}:${hashHex.slice(0, 16)}`;
  }

  async function generateTokens(
    ctx: Context,
    value: {
      type: string;
      properties: any;
      subject: string;
      clientID: string;
      ttl: {
        access: number;
        refresh: number;
      };
      timeUsed?: number;
      nextToken?: string;
    },
    opts?: {
      generateRefreshToken?: boolean;
      // If scope includes 'openid', generate and include an ID token
      generateIDToken?: boolean;
    },
  ) {
    const refreshToken = value.nextToken ?? crypto.randomUUID();
    if (opts?.generateRefreshToken ?? true) {
      /**
       * Generate and store the next refresh token after the one we are currently returning.
       * Reserving these in advance avoids concurrency issues with multiple refreshes.
       * Similar treatment should be given to any other values that may have race conditions,
       * for example if a jti claim was added to the access token.
       */
      const refreshValue = {
        ...value,
        nextToken: crypto.randomUUID(),
      };
      delete refreshValue.timeUsed;
      await Storage.set(
        storage!,
        ["oauth:refresh", value.subject, refreshToken],
        refreshValue,
        value.ttl.refresh,
      );
    }

    const iss = issuer(ctx);

    return {
      access: await new SignJWT({
        mode: "access",
        type: value.type,
        properties: value.properties,
        aud: value.clientID,
        iss,
        sub: value.subject,
      })
        .setExpirationTime(
          Math.floor((value.timeUsed ?? Date.now()) / 1000 + value.ttl.access),
        )
        .setProtectedHeader(
          await signingKey.then((k) => ({
            alg: k.alg,
            kid: k.id,
            typ: "JWT",
          })),
        )
        .sign(await signingKey.then((item) => item.private)),
      refresh: [value.subject, refreshToken].join(":"),
      id_token: opts?.generateIDToken
        ? await new SignJWT({
            // Standard claims
            iss,
            sub: value.subject,
            aud: value.clientID,
            // Additional claims from the user's properties
            ...value.properties,
          })
            .setExpirationTime(Math.floor(Date.now() / 1000 + value.ttl.access))
            .setIssuedAt()
            .setProtectedHeader(
              await signingKey.then((k) => ({
                alg: k.alg,
                kid: k.id,
                typ: "JWT",
              })),
            )
            .sign(await signingKey.then((item) => item.private))
        : undefined,
    };
  }

  async function decrypt(value: string) {
    return JSON.parse(
      new TextDecoder().decode(
        await compactDecrypt(
          value,
          await encryptionKey.then((v) => v.private),
        ).then((value) => value.plaintext),
      ),
    );
  }

  function issuer(ctx: Context) {
    const url = new URL(ctx.req.url);
    const host = ctx.req.header("x-forwarded-host") ?? url.host;
    return url.protocol + "//" + host;
  }

  const app = new Hono<{
    Variables: {
      authorization: AuthorizationState;
    };
  }>();

  for (const [name, value] of Object.entries(input.providers)) {
    const route = new Hono<any>();
    route.use(async (c, next) => {
      c.set("provider", name);
      await next();
    });
    value.init(route, {
      name,
      ...auth,
    });
    app.route(`/${name}`, route);
  }

  app.get(
    "/.well-known/jwks.json",
    cors({
      origin: "*",
      allowHeaders: ["*"],
      allowMethods: ["GET"],
      credentials: false,
    }),
    async (c) => {
      const all = await allSigning;
      return c.json({
        keys: all.map((item) => ({
          ...item.jwk,
          exp: item.expired
            ? Math.floor(item.expired.getTime() / 1000)
            : undefined,
        })),
      });
    },
  );

  // OpenID Connect Discovery 1.0
  // This endpoint provides configuration information about the OpenID Connect provider
  app.get(
    "/.well-known/openid-configuration",
    cors({
      origin: "*",
      allowHeaders: ["*"],
      allowMethods: ["GET"],
      credentials: false,
    }),
    async (c) => {
      const iss = issuer(c);
      return c.json({
        // REQUIRED. URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier
        issuer: iss,
        // REQUIRED. URL of the OP's OAuth 2.0 Authorization Endpoint
        authorization_endpoint: `${iss}/authorize`,
        // REQUIRED. URL of the OP's OAuth 2.0 Token Endpoint
        token_endpoint: `${iss}/token`,
        // RECOMMENDED. URL of the OP's JSON Web Key Set document
        jwks_uri: `${iss}/.well-known/jwks.json`,
        // RECOMMENDED. JSON array containing a list of the OAuth 2.0 scope values that this server supports
        scopes_supported: [
          "openid",
          "offline_access",
          // TODO(sam): do we need these?
          // "email",
          // "groups",
          // "profile",
        ],
        // REQUIRED. JSON array containing a list of the OAuth 2.0 response_type values that this OP supports
        response_types_supported: ["code", "token"],
        // REQUIRED. JSON array containing a list of the Subject Identifier types that this OP supports
        subject_types_supported: [
          "public",
          // TODO(sam): support pairwise?
        ],
        // REQUIRED. JSON array containing a list of the JWS signing algorithms supported by the OP for the ID Token
        id_token_signing_alg_values_supported: [
          "ES256",
          // TODO(sam): support RS256? can flyte use ES256?
          // "RS256",
        ],
        // REQUIRED. JSON array containing a list of Client Authentication methods supported by this Token Endpoint
        token_endpoint_auth_methods_supported: [
          "client_secret_basic",
          "client_secret_post",
          // TODO(sam): support private_key_jwt and client_secret_jwt
          // private_key_jwt
          // client_secret_jwt
        ],
        // RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for
        claims_supported: [
          "sub",
          "iss",
          "aud",
          "exp",
          "iat",
          // TODO(sam): do we need these?
          // "email",
          // "email_verified",
          // "locale",
          // "name",
          // "preferred_username",
          // "at_hash",
        ],
        // OPTIONAL. URL of the authorization server's OAuth 2.0 Dynamic Client Registration endpoint
        registration_endpoint: `${iss}/client`,
        // OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports
        grant_types_supported: [
          "authorization_code",
          "refresh_token",
          // TODO(sam): support device_code and token_exchange
          // "urn:ietf:params:oauth:grant-type:device_code",
          // "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        // OPTIONAL. URL of the OP's UserInfo Endpoint
        userinfo_endpoint: `${iss}/userinfo`,
      });
    },
  );

  app.get(
    "/.well-known/oauth-authorization-server",
    cors({
      origin: "*",
      allowHeaders: ["*"],
      allowMethods: ["GET"],
      credentials: false,
    }),
    async (c) => {
      const iss = issuer(c);
      return c.json({
        issuer: iss,
        authorization_endpoint: `${iss}/authorize`,
        token_endpoint: `${iss}/token`,
        jwks_uri: `${iss}/.well-known/jwks.json`,
        response_types_supported: ["code", "token"],
      });
    },
  );

  app.post(
    "/token",
    cors({
      origin: "*",
      allowHeaders: ["*"],
      allowMethods: ["POST"],
      credentials: false,
    }),
    async (c) => {
      const form = await c.req.formData();
      const grantType = form.get("grant_type");

      if (grantType === "authorization_code") {
        // Get client credentials from either Authorization header (Basic auth) or form body
        let clientID: string | undefined;
        let clientSecret: string | undefined;

        // Check Authorization header for Basic auth
        const authHeader = c.req.header("Authorization");
        if (authHeader?.startsWith("Basic ")) {
          try {
            const credentials = Buffer.from(
              authHeader.slice(6),
              "base64",
            ).toString();
            const [id, secret] = credentials.split(":");
            if (id && secret) {
              clientID = id;
              clientSecret = secret;
            }
          } catch (err) {
            return c.json(
              {
                error: "invalid_client",
                error_description: "Invalid Authorization header format",
              },
              401,
            );
          }
        } else {
          // Fallback to form parameters (client_secret_post)
          clientID = form.get("client_id")?.toString();
          clientSecret = form.get("client_secret")?.toString();
        }

        // Verify client credentials if provided
        if (clientID && clientSecret) {
          // if both of these exist, we are assuming this is an OIDC client
          const client = await Storage.get<{
            client_id: string;
            client_secret: any;
          }>(storage, ["oauth:client", clientID]);

          if (!client) {
            return c.json(
              {
                error: "invalid_client",
                error_description: "Unknown client",
              },
              401,
            );
          }

          // Verify client secret using the shared hasher instance
          const isValid = await hasher.verify(
            clientSecret,
            client.client_secret,
          );
          if (!isValid) {
            return c.json(
              {
                error: "invalid_client",
                error_description: "Invalid client credentials",
              },
              401,
            );
          }
        }

        const code = form.get("code");
        if (!code)
          return c.json(
            {
              error: "invalid_request",
              error_description: "Missing code",
            },
            400,
          );
        const key = ["oauth:code", code.toString()];
        const payload = await Storage.get<{
          type: string;
          properties: any;
          clientID: string;
          redirectURI: string;
          subject: string;
          ttl: {
            access: number;
            refresh: number;
          };
          pkce?: AuthorizationState["pkce"];
          scope?: string;
        }>(storage, key);
        if (!payload) {
          return c.json(
            {
              error: "invalid_grant",
              error_description: "Authorization code has been used or expired",
            },
            400,
          );
        }

        await Storage.remove(storage, key);
        if (payload.redirectURI !== form.get("redirect_uri")) {
          return c.json(
            {
              error: "invalid_redirect_uri",
              error_description: "Redirect URI mismatch",
            },
            400,
          );
        }
        if (payload.clientID !== clientID) {
          return c.json(
            {
              error: "unauthorized_client",
              error_description:
                "Client is not authorized to use this authorization code",
            },
            403,
          );
        }

        if (payload.pkce) {
          const codeVerifier = form.get("code_verifier")?.toString();
          if (!codeVerifier)
            return c.json(
              {
                error: "invalid_grant",
                error_description: "Missing code_verifier",
              },
              400,
            );

          if (
            !(await validatePKCE(
              codeVerifier,
              payload.pkce.challenge,
              payload.pkce.method,
            ))
          ) {
            return c.json(
              {
                error: "invalid_grant",
                error_description: "Code verifier does not match",
              },
              400,
            );
          }
        }
        const tokens = await generateTokens(c, payload, {
          // If scope includes 'openid', generate and include an ID token
          generateIDToken: payload.scope?.includes("openid"),
        });
        const response: any = {
          access_token: tokens.access,
          refresh_token: tokens.refresh,
          token_type: "Bearer",
          expires_in: payload.ttl.access,
          id_token: tokens.id_token,
        };

        return c.json(response);
      }

      if (grantType === "refresh_token") {
        const refreshToken = form.get("refresh_token");
        if (!refreshToken)
          return c.json(
            {
              error: "invalid_request",
              error_description: "Missing refresh_token",
            },
            400,
          );
        const splits = refreshToken.toString().split(":");
        const token = splits.pop()!;
        const subject = splits.join(":");
        const key = ["oauth:refresh", subject, token];
        const payload = await Storage.get<{
          type: string;
          properties: any;
          clientID: string;
          subject: string;
          ttl: {
            access: number;
            refresh: number;
          };
          nextToken: string;
          timeUsed?: number;
          scope?: string;
        }>(storage, key);
        if (!payload) {
          return c.json(
            {
              error: "invalid_grant",
              error_description: "Refresh token has been used or expired",
            },
            400,
          );
        }
        const generateRefreshToken = !payload.timeUsed;
        if (ttlRefreshReuse <= 0) {
          // no reuse interval, remove the refresh token immediately
          await Storage.remove(storage, key);
        } else if (!payload.timeUsed) {
          payload.timeUsed = Date.now();
          await Storage.set(
            storage,
            key,
            payload,
            ttlRefreshReuse + ttlRefreshRetention,
          );
        } else if (Date.now() > payload.timeUsed + ttlRefreshReuse * 1000) {
          // token was reused past the allowed interval
          await auth.invalidate(subject);
          return c.json(
            {
              error: "invalid_grant",
              error_description: "Refresh token has been used or expired",
            },
            400,
          );
        }
        const tokens = await generateTokens(c, payload, {
          generateRefreshToken,
          // TODO(sam): should we generate an ID token for refresh tokens?
          // generateIDToken: payload.scope?.includes("openid"),
        });
        return c.json({
          access_token: tokens.access,
          refresh_token: tokens.refresh,
        });
      }

      if (grantType === "client_credentials") {
        const provider = form.get("provider");
        if (!provider)
          return c.json({ error: "missing `provider` form value" }, 400);
        const match = input.providers[provider.toString()];
        if (!match)
          return c.json({ error: "invalid `provider` query parameter" }, 400);
        if (!match.client)
          return c.json(
            { error: "this provider does not support client_credentials" },
            400,
          );
        const clientID = form.get("client_id");
        const clientSecret = form.get("client_secret");
        if (!clientID)
          return c.json({ error: "missing `client_id` form value" }, 400);
        if (!clientSecret)
          return c.json({ error: "missing `client_secret` form value" }, 400);
        const response = await match.client({
          clientID: clientID.toString(),
          clientSecret: clientSecret.toString(),
          params: Object.fromEntries(form) as Record<string, string>,
        });
        return input.success(
          {
            async subject(type, properties, opts) {
              const tokens = await generateTokens(c, {
                type: type as string,
                subject:
                  opts?.subject || (await resolveSubject(type, properties)),
                properties,
                clientID: clientID.toString(),
                ttl: {
                  access: opts?.ttl?.access ?? ttlAccess,
                  refresh: opts?.ttl?.refresh ?? ttlRefresh,
                },
              });
              return c.json({
                access_token: tokens.access,
                refresh_token: tokens.refresh,
              });
            },
          },
          {
            provider: provider.toString(),
            ...response,
          },
          c.req.raw,
        );
      }

      throw new Error("Invalid grant_type");
    },
  );

  // OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)
  // This endpoint allows OAuth 2.0 clients to register with the authorization server,
  // providing client metadata parameters and receiving client credentials.
  app.post(
    "/client",
    cors({
      origin: "*",
      allowHeaders: ["*"],
      allowMethods: ["POST"],
      credentials: false,
    }),
    async (c) => {
      // Validate rootClientSecret from Authorization header
      if (!input.oidc?.rootClientSecret) {
        return c.json(
          {
            error: "invalid_request",
            error_description: "OIDC registration is not enabled",
          },
          400,
        );
      }

      const authHeader = c.req.header("Authorization");
      if (!authHeader?.startsWith("Bearer ")) {
        return c.json(
          {
            error: "invalid_client",
            error_description: "Missing or invalid Authorization header",
          },
          401,
        );
      }

      const secret = authHeader.substring(7); // Remove "Bearer " prefix
      if (secret !== input.oidc.rootClientSecret) {
        return c.json(
          {
            error: "invalid_client",
            error_description: "Invalid root client secret",
          },
          401,
        );
      }

      const body = await c.req.json();

      // redirect_uris is REQUIRED for clients using the authorization code grant type
      // or implicit grant type. This array MUST contain at least one redirect URI.
      if (
        !body.redirect_uris ||
        !Array.isArray(body.redirect_uris) ||
        body.redirect_uris.length === 0
      ) {
        return c.json(
          {
            error: "invalid_request",
            error_description: "redirect_uris must be a non-empty array",
          },
          400,
        );
      }

      // Generate client credentials
      const clientID = crypto.randomUUID();
      const rawClientSecret = crypto.randomUUID() + crypto.randomUUID();
      const hashedClientSecret = await hasher.hash(rawClientSecret);

      // Create client configuration with metadata
      // The authorization server MAY include default values for any registered
      // metadata values used by the client that the client omits
      const client = {
        // REQUIRED. Unique client identifier.
        client_id: clientID,
        // OPTIONAL. Hashed client secret. Required for confidential clients.
        client_secret: hashedClientSecret,
        // OPTIONAL. Human-readable name of the client.
        client_name: body.client_name || clientID,
        // REQUIRED for authorization code and implicit grants.
        redirect_uris: body.redirect_uris,
        // OPTIONAL. Array of OAuth 2.0 grant types supported by the client.
        grant_types: body.grant_types || ["authorization_code"],
        // OPTIONAL. Authentication method for the token endpoint.
        token_endpoint_auth_method:
          body.token_endpoint_auth_method || "client_secret_post",
        // OPTIONAL. Space-separated string of OAuth 2.0 scope values.
        scope: body.scope || "openid",
        // OPTIONAL. Time at which the client was registered.
        created_at: Math.floor(Date.now() / 1000),
        // TODO(sam): I injected this since we need it to validate access to the tenant by github
        // OAuth 2.0 spec is flexible and servers can accept arbitrary metadata
        // TODO(sam): figure out how to do this in a more generic/extensible way.
        org_id: body.org_id,
      } satisfies OidcClient;

      // The authorization server stores the client metadata in a persistent storage
      await Storage.set(
        storage,
        ["oauth:client", clientID],
        client,
        // TODO(sam): should this follow the same ttl as the access token? or have its own?
        undefined,
      );

      // The authorization server's response MUST include the client identifier,
      // and MAY include additional metadata fields registered by the client.
      // Return the plain client_secret only in the response, not in storage.
      return c.json({
        ...client,
        client_secret: rawClientSecret,
      });
    },
  );

  // OAuth 2.0 Dynamic Client Registration Management Protocol (RFC 7592)
  // This endpoint allows OAuth 2.0 clients to update their registration metadata
  app.put(
    "/client/:client_id",
    cors({
      origin: "*",
      allowHeaders: ["*"],
      allowMethods: ["PUT"],
      credentials: false,
    }),
    async (c) => {
      const clientID = c.req.param("client_id");

      try {
        const body = await c.req.json();

        // Validate required fields first
        if (
          !body.redirect_uris ||
          !Array.isArray(body.redirect_uris) ||
          body.redirect_uris.length === 0
        ) {
          return c.json(
            {
              error: "invalid_request",
              error_description: "redirect_uris must be a non-empty array",
            },
            400 as const,
          );
        }

        // Then validate client credentials
        const existingClient = await validateClientCredentials(c, clientID);

        // Create updated client configuration
        // Note: client_id and client_secret cannot be updated
        const updatedClient = {
          ...existingClient,
          client_name: body.client_name || existingClient.client_name,
          redirect_uris: body.redirect_uris,
          grant_types: body.grant_types || existingClient.grant_types,
          token_endpoint_auth_method:
            body.token_endpoint_auth_method ||
            existingClient.token_endpoint_auth_method,
          scope: body.scope || existingClient.scope,
          // TODO(sam): I injected this since we need it to validate access to the tenant by github
          // OAuth 2.0 spec is flexible and servers can accept arbitrary metadata
          // TODO(sam): figure out how to do this in a more generic/extensible way.
          org_id: body.org_id || existingClient.org_id,
        } satisfies OidcClient;

        // Update client in storage
        await Storage.set(
          storage,
          ["oauth:client", clientID],
          updatedClient,
          undefined, // Store indefinitely
        );

        // Return updated client metadata
        // Note: client_secret is not included in the response for security
        const { client_secret, ...responseData } = updatedClient;
        return c.json(responseData);
      } catch (err) {
        if (err instanceof OauthError) {
          return c.json(
            {
              error: err.error,
              error_description: err.description,
            },
            err.status as 400 | 401 | 404,
          );
        }
        throw err;
      }
    },
  );

  // OAuth 2.0 Dynamic Client Registration Management Protocol (RFC 7592)
  // This endpoint allows OAuth 2.0 clients to delete their registration
  app.delete(
    "/client/:client_id",
    cors({
      origin: "*",
      allowHeaders: ["*"],
      allowMethods: ["DELETE"],
      credentials: false,
    }),
    async (c) => {
      const clientID = c.req.param("client_id");

      try {
        await validateClientCredentials(c, clientID);

        // Delete client from storage
        await Storage.remove(storage, ["oauth:client", clientID]);

        // Return 204 No Content on successful deletion
        return new Response(null, { status: 204 });
      } catch (err) {
        if (err instanceof OauthError) {
          return c.json(
            {
              error: err.error,
              error_description: err.description,
            },
            err.status as 400 | 401 | 404,
          );
        }
        throw err;
      }
    },
  );

  /**
   * Validates client credentials using Basic authentication.
   * Returns the client if authentication is successful, or throws an OauthError if not.
   *
   * This is for dynamically registered clients.
   */
  async function validateClientCredentials(
    c: Context,
    clientID: string,
  ): Promise<OidcClient> {
    // Get existing client registration
    const existingClient = await Storage.get<OidcClient>(storage, [
      "oauth:client",
      clientID,
    ]);

    if (!existingClient) {
      throw new OauthError("invalid_client", "Client not found", 404);
    }

    // Verify client authentication using client_secret
    const authHeader = c.req.header("Authorization");
    if (!authHeader?.startsWith("Basic ")) {
      throw new OauthError(
        "invalid_client",
        "Missing or invalid Authorization header",
        401,
      );
    }

    try {
      const credentials = Buffer.from(authHeader.slice(6), "base64").toString();
      const [id, secret] = credentials.split(":");
      if (id !== clientID) {
        throw new OauthError("invalid_client", "Client ID mismatch", 401);
      }

      const isValid = await hasher.verify(secret, existingClient.client_secret);
      if (!isValid) {
        throw new OauthError(
          "invalid_client",
          "Invalid client credentials",
          401,
        );
      }

      return existingClient;
    } catch (err) {
      if (err instanceof OauthError) throw err;
      throw new OauthError(
        "invalid_client",
        "Invalid Authorization header format",
        401,
      );
    }
  }

  app.get("/authorize", async (c) => {
    const provider = c.req.query("provider");
    const response_type = c.req.query("response_type");
    const redirect_uri = c.req.query("redirect_uri");
    const state = c.req.query("state");
    const client_id = c.req.query("client_id");
    const audience = c.req.query("audience");
    const code_challenge = c.req.query("code_challenge");
    const code_challenge_method = c.req.query("code_challenge_method");
    const scope = c.req.query("scope");

    const authorization: AuthorizationState = {
      response_type,
      redirect_uri,
      state,
      client_id,
      audience,
      scope,
      pkce:
        code_challenge && code_challenge_method
          ? {
              challenge: code_challenge,
              method: code_challenge_method,
            }
          : undefined,
    } as AuthorizationState;
    c.set("authorization", authorization);

    if (!redirect_uri) {
      return c.text("Missing redirect_uri", { status: 400 });
    }

    if (!response_type) {
      throw new MissingParameterError("response_type");
    }

    if (!client_id) {
      throw new MissingParameterError("client_id");
    }

    // When 'openid' scope is requested, this indicates an OpenID Connect authentication request.
    // The Authorization Server MUST verify that the client is registered to use the requested scope.
    if (scope?.includes("openid")) {
      const client = await Storage.get<{
        client_id: string;
        redirect_uris: string[];
        scope: string;
      }>(storage, ["oauth:client", client_id]);

      // The authorization server MUST verify that a client exists with the provided client identifier
      if (!client) {
        return c.json(
          {
            error: "invalid_client",
            error_description: `Client ${client_id} not found`,
          },
          400,
        );
      }

      // If the request fails due to a missing, invalid, or mismatching redirection URI,
      // the authorization server SHOULD inform the resource owner of the error.
      if (!client.redirect_uris.includes(redirect_uri)) {
        return c.json(
          {
            error: "unauthorized_client",
            error_description: `Client ${client_id} is not authorized to use this redirect_uri: ${redirect_uri}`,
          },
          400,
        );
      }

      // The Authorization Server MUST verify that the Client is authorized to use the requested scope
      // values. 'openid' scope is REQUIRED for OpenID Connect Authentication requests.
      if (!client.scope?.includes("openid")) {
        return c.json(
          {
            error: "invalid_scope",
            error_description: "Client is not authorized for openid scope",
          },
          400,
        );
      }
    }

    if (input.start) {
      await input.start(c.req.raw);
    }

    if (
      !(await allow(
        {
          clientID: client_id,
          redirectURI: redirect_uri,
          audience,
        },
        c.req.raw,
      ))
    )
      throw new UnauthorizedClientError(client_id, redirect_uri);

    await auth.set(c, "authorization", 60 * 60 * 24, authorization);
    if (provider) return c.redirect(`/${provider}/authorize`);
    const providers = Object.keys(input.providers);
    if (providers.length === 1) return c.redirect(`/${providers[0]}/authorize`);
    return auth.forward(
      c,
      await select(
        Object.fromEntries(
          Object.entries(input.providers).map(([key, value]) => [
            key,
            value.type,
          ]),
        ),
        c.req.raw,
      ),
    );
  });

  app.onError(async (err, c) => {
    console.error(err);
    if (err instanceof UnknownStateError) {
      return auth.forward(c, await error(err, c.req.raw));
    }
    const oauth =
      err instanceof OauthError
        ? err
        : new OauthError("server_error", err.message);

    // For other errors, redirect with error parameters
    const authorization = await getAuthorization(c);
    const url = new URL(authorization.redirect_uri);
    url.searchParams.set("error", oauth.error);
    url.searchParams.set("error_description", oauth.description);
    return c.redirect(url.toString());
  });

  app.get(
    "/userinfo",
    cors({
      origin: "*",
      allowHeaders: ["*", "Authorization"],
      allowMethods: ["GET"],
      credentials: false,
    }),
    async (c) => {
      // Get the access token from the Authorization header
      const authHeader = c.req.header("Authorization");
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return c.json(
          {
            error: "invalid_token",
            error_description: "Missing or invalid Authorization header",
          },
          401,
        );
      }

      const accessToken = authHeader.substring(7); // Remove "Bearer " prefix

      try {
        // Verify the access token using all available signing keys
        const keys = await allSigning;
        let payload;

        for (const key of keys) {
          try {
            const { payload: decoded } = await jwtVerify(
              accessToken,
              key.public,
              {
                issuer: issuer(c),
              },
            );
            payload = decoded as {
              mode: string;
              type: string;
              properties: Record<string, any>;
              sub: string;
            };
            break;
          } catch (err) {
            continue; // Try next key if verification fails
          }
        }

        if (!payload || payload.mode !== "access") {
          return c.json(
            {
              error: "invalid_token",
              error_description: "Invalid access token",
            },
            401,
          );
        }

        // Return standard claims and user properties as claims
        return c.json({
          sub: payload.sub,
          ...payload.properties,
        });
      } catch (err) {
        return c.json(
          {
            error: "invalid_token",
            error_description: "Invalid access token",
          },
          401,
        );
      }
    },
  );

  return app;
}

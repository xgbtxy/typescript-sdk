import type {
    AuthMetadataOptions as NeutralAuthMetadataOptions,
    OAuthMetadata,
    OAuthProtectedResourceMetadata
} from '@modelcontextprotocol/server';
import { buildOAuthProtectedResourceMetadata, OAuthError, OAuthErrorCode } from '@modelcontextprotocol/server';
import cors from 'cors';
import type { RequestHandler, Router } from 'express';
import express from 'express';

// Dev-only escape hatch: allow http:// issuer URLs (e.g., for local testing).
const allowInsecureIssuerUrl =
    process.env.MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL === 'true' || process.env.MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL === '1';
if (allowInsecureIssuerUrl) {
    // eslint-disable-next-line no-console
    console.warn('MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL is enabled - HTTP issuer URLs are allowed. Do not use in production.');
}

/**
 * Express middleware that rejects HTTP methods not in the supplied allow-list
 * with a 405 Method Not Allowed and an OAuth-style error body. Used by
 * {@link metadataHandler} to restrict metadata endpoints to GET/OPTIONS.
 */
export function allowedMethods(allowed: string[]): RequestHandler {
    return (req, res, next) => {
        if (allowed.includes(req.method)) {
            next();
            return;
        }
        const error = new OAuthError(OAuthErrorCode.MethodNotAllowed, `The method ${req.method} is not allowed for this endpoint`);
        res.status(405).set('Allow', allowed.join(', ')).json(error.toResponseObject());
    };
}

function stripTrailingSlash(path: string): string {
    return path.length > 1 && path.endsWith('/') ? path.slice(0, -1) : path;
}

function metadataMiddleware(metadata: OAuthMetadata | OAuthProtectedResourceMetadata): RequestHandler[] {
    return [
        // Metadata documents must be fetchable from web-based MCP clients on any origin.
        cors(),
        allowedMethods(['GET', 'OPTIONS']),
        (_req, res) => {
            res.status(200).json(metadata);
        }
    ];
}

function mountExactPath(router: Router, path: string, handlers: RequestHandler[]): void {
    const expected = stripTrailingSlash(path);
    const sub = express.Router();
    sub.use(...handlers);
    router.use((req, res, next) => {
        if (stripTrailingSlash(req.path) !== expected) {
            next();
            return;
        }
        sub(req, res, next);
    });
}

/**
 * Builds a small Express router that serves the given OAuth metadata document
 * at `/` as JSON, with permissive CORS and a GET/OPTIONS method allow-list.
 *
 * Used by {@link mcpAuthMetadataRouter} for both the Authorization Server and
 * Protected Resource metadata endpoints.
 */
export function metadataHandler(metadata: OAuthMetadata | OAuthProtectedResourceMetadata): RequestHandler {
    const router = express.Router();
    router.all('/', ...metadataMiddleware(metadata));
    return router;
}

/**
 * Options for {@link mcpAuthMetadataRouter}: the runtime-neutral
 * `AuthMetadataOptions` from `@modelcontextprotocol/server`. The
 * insecure-issuer escape hatch can also be enabled here by the
 * `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL` environment variable.
 */
export type { AuthMetadataOptions } from '@modelcontextprotocol/server';

/**
 * Builds an Express router that serves the two OAuth discovery documents an
 * MCP server acting purely as a Resource Server needs to expose:
 *
 *  - `/.well-known/oauth-protected-resource[/<path>]` — RFC 9728 Protected
 *    Resource Metadata, derived from the supplied options.
 *  - `/.well-known/oauth-authorization-server` — RFC 8414 Authorization
 *    Server Metadata, passed through verbatim from the supplied `oauthMetadata`.
 *
 * Mount this router at the application root:
 *
 * ```ts
 * app.use(mcpAuthMetadataRouter({ oauthMetadata, resourceServerUrl }));
 * ```
 *
 * Pair with `requireBearerAuth` on your `/mcp` route and pass
 * `getOAuthProtectedResourceMetadataUrl` as its `resourceMetadataUrl`
 * so unauthenticated clients can discover the AS from the 401 challenge.
 */
export function mcpAuthMetadataRouter(options: NeutralAuthMetadataOptions): Router {
    if (options.dangerouslyAllowInsecureIssuerUrl && !allowInsecureIssuerUrl) {
        // The env-var path warns at module load; enabling via the option is
        // equally loud so an insecure issuer can never be allowed silently.
        // eslint-disable-next-line no-console
        console.warn('dangerouslyAllowInsecureIssuerUrl is enabled - HTTP issuer URLs are allowed. Do not use in production.');
    }
    const protectedResourceMetadata = buildOAuthProtectedResourceMetadata({
        ...options,
        // The env var and the option are both honored; either enables it.
        dangerouslyAllowInsecureIssuerUrl: allowInsecureIssuerUrl || options.dangerouslyAllowInsecureIssuerUrl
    });

    const router = express.Router();

    // Match literally (tolerating a single trailing slash) so RFC 3986 path
    // characters are not parsed as route syntax and subpaths fall through.
    const rsPath = stripTrailingSlash(new URL(options.resourceServerUrl.href).pathname);
    mountExactPath(
        router,
        `/.well-known/oauth-protected-resource${rsPath === '/' ? '' : rsPath}`,
        metadataMiddleware(protectedResourceMetadata)
    );

    // Mirror the AS metadata at this origin for clients that look here first.
    mountExactPath(router, '/.well-known/oauth-authorization-server', metadataMiddleware(options.oauthMetadata));

    return router;
}

// Re-exported from the runtime-neutral home in @modelcontextprotocol/server.
export { getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/server';

import type { OAuthMetadata } from '@modelcontextprotocol/server';
import express from 'express';
import supertest from 'supertest';

import { mcpAuthMetadataRouter, metadataHandler } from '../../src/auth/metadataRouter';

const oauthMetadata: OAuthMetadata = {
    issuer: 'https://auth.example.com/',
    authorization_endpoint: 'https://auth.example.com/authorize',
    token_endpoint: 'https://auth.example.com/token',
    response_types_supported: ['code']
};

describe('mcpAuthMetadataRouter literal path matching', () => {
    it.each([
        'https://api.example.com/v1/c++/mcp',
        'https://api.example.com/v1/(beta)/mcp',
        'https://api.example.com/v1/mcp:serve',
        'https://api.example.com/v1/foo*bar'
    ])('serves PRM literally when resourceServerUrl contains path-to-regexp characters (%s)', async resourceUrl => {
        const app = express();
        const url = new URL(resourceUrl);
        app.use(mcpAuthMetadataRouter({ oauthMetadata, resourceServerUrl: url }));

        const exactPath = `/.well-known/oauth-protected-resource${url.pathname}`;
        const exact = await supertest(app).get(exactPath);
        expect(exact.status).toBe(200);
        expect(exact.body.resource).toBe(url.href);

        const unrelated = await supertest(app).get('/.well-known/oauth-protected-resource/v1/mcpUNRELATED');
        expect(unrelated.status).toBe(404);

        const unrelatedStar = await supertest(app).get('/.well-known/oauth-protected-resource/v1/fooUNRELATED');
        expect(unrelatedStar.status).toBe(404);
    });

    it('serves PRM both with and without a trailing slash when resourceServerUrl ends in a slash', async () => {
        const app = express();
        app.use(mcpAuthMetadataRouter({ oauthMetadata, resourceServerUrl: new URL('https://api.example.com/mcp/') }));

        for (const path of ['/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-protected-resource/mcp/']) {
            const res = await supertest(app).get(path);
            expect(res.status).toBe(200);
            expect(res.body.resource).toBe('https://api.example.com/mcp/');
        }
    });

    it('lets unrelated subpaths under the well-known prefix fall through untouched', async () => {
        const app = express();
        app.use(mcpAuthMetadataRouter({ oauthMetadata, resourceServerUrl: new URL('https://api.example.com/') }));
        app.get('/.well-known/oauth-protected-resource/other', (_req, res) => {
            res.status(200).json({ custom: 'get' });
        });
        app.post('/.well-known/oauth-protected-resource/other', (_req, res) => {
            res.status(201).json({ custom: 'post' });
        });
        app.post('/.well-known/oauth-authorization-server/tenant', (_req, res) => {
            res.status(201).json({ custom: 'as-tenant' });
        });

        const getSub = await supertest(app).get('/.well-known/oauth-protected-resource/other');
        expect(getSub.status).toBe(200);
        expect(getSub.body).toEqual({ custom: 'get' });
        expect(getSub.headers['access-control-allow-origin']).toBeUndefined();

        const postSub = await supertest(app).post('/.well-known/oauth-protected-resource/other');
        expect(postSub.status).toBe(201);
        expect(postSub.body).toEqual({ custom: 'post' });

        const postAsSub = await supertest(app).post('/.well-known/oauth-authorization-server/tenant');
        expect(postAsSub.status).toBe(201);
        expect(postAsSub.body).toEqual({ custom: 'as-tenant' });

        const optionsSub = await supertest(app).options('/.well-known/oauth-protected-resource/nonexistent');
        expect(optionsSub.status).toBe(404);
    });

    it('scopes metadataHandler CORS and method checks to the mounted root only', async () => {
        const app = express();
        app.use('/meta', metadataHandler(oauthMetadata));
        app.post('/meta/child', (_req, res) => {
            res.status(201).json({ child: true });
        });

        expect((await supertest(app).get('/meta')).status).toBe(200);
        expect((await supertest(app).options('/meta')).status).toBe(204);
        expect((await supertest(app).post('/meta')).status).toBe(405);

        const childPost = await supertest(app).post('/meta/child');
        expect(childPost.status).toBe(201);
        expect(childPost.headers['access-control-allow-origin']).toBeUndefined();
    });
});

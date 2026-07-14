import { request, type RequestOptions } from 'node:https';

import type { IncomingHttpHeaders } from 'node:http';

type RequestBody = string | Buffer | Record<string, unknown> | unknown[] | null;

export type HttpsRequestOptions = RequestOptions & {
  body?: RequestBody;
};

export type HttpsResponse<T = unknown> = {
  statusCode?: number;
  statusMessage?: string;
  headers: IncomingHttpHeaders;
  body: string;
  data: T;
};

export async function httpsRequest<T = unknown>(options: HttpsRequestOptions): Promise<HttpsResponse<T>> {
  return new Promise((resolve, reject) => {
    const { body, headers = {}, ...requestOptions } = options;

    const finalHeaders: Record<string, string | number | string[]> = {
      ...(headers as Record<string, string | number | string[]>)
    };

    let payload: string | Buffer | undefined;

    if (body != null) {
      if (typeof body === 'string' || Buffer.isBuffer(body)) {
        payload = body;
      } else {
        payload = JSON.stringify(body);

        if (!hasHeader(finalHeaders, 'content-type')) {
          finalHeaders['Content-Type'] = 'application/json';
        }
      }

      if (!hasHeader(finalHeaders, 'content-length')) {
        finalHeaders['Content-Length'] = Buffer.byteLength(payload);
      }
    }

    const req = request(
      {
        ...requestOptions,
        headers: finalHeaders
      },
      (res) => {
        const chunks: Buffer[] = [];

        res.on('data', (chunk) => {
          chunks.push(Buffer.from(chunk));
        });

        res.on('end', () => {
          const rawBody = Buffer.concat(chunks).toString('utf8');

          let data: T;

          try {
            data = JSON.parse(rawBody) as T;
          } catch {
            data = rawBody as T;
          }

          resolve({
            statusCode: res.statusCode,
            statusMessage: res.statusMessage,
            headers: res.headers,
            body: rawBody,
            data
          });
        });
      }
    );

    req.on('error', reject);
    req.end(payload);
  });
}

function hasHeader(headers: Record<string, unknown>, name: string): boolean {
  return Object.keys(headers).some((key) => key.toLowerCase() === name.toLowerCase());
}

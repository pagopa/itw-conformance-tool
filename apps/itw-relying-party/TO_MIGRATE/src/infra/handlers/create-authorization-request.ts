import { Config } from "@/config";
import { BadRequestError } from "@/errors";
import { NonceRepository, insertNonce } from "@/nonce";
import { RequestObjectRepository, insertRequestObject } from "@/request-object";
import { AuthorizationRequest, FlowType } from "@/schemas";
import * as crypto from "crypto";
import { DcqlQuery } from "dcql";
import jwt from "jsonwebtoken";
import * as uuid from "uuid";

function generateNonce() {
  return crypto.randomBytes(32).toString("hex"); // this is the correct way to generate a nonce
  // return "d356b2772328066e4382fb5b7bda37146f33fae485e52782c876f759043ab500"; // this is a mock nonce for testing purposes
}

function getTrustAnchorEC() {
  return "eyJhbGciOiJFUzI1NiIsImtpZCI6IlVtYnVuUWwyMEFXTU9ybmlMbk52QndNa3MtV2tYTDIxdzZ1VnpmRUwxOE0ifQ.eyJpc3MiOiJodHRwczovL2ZvbzExLmJsb2IuY29yZS53aW5kb3dzLm5ldC90YS10ZXN0Iiwic3ViIjoiaHR0cHM6Ly9mb28xMS5ibG9iLmNvcmUud2luZG93cy5uZXQvdGEtdGVzdCIsImp3a3MiOnsia2V5cyI6W3sia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJCTkQyc19VYW1xaDI5VEtMY2xuM3htRkNzS2tGVE45WVRoVF9ZRmR1el9ZIiwieSI6Ind3Iiwia2lkIjoiVW1idW5RbDIwQVdNT3JuaUxuTnZCd01rcy1Xa1hMMjF3NnVWemZFTDE4TSJ9XX0sImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxODAwMDAwMDAwLCJtZXRhZGF0YSI6eyJmZWRlcmF0aW9uX2VudGl0eSI6eyJmZWRlcmF0aW9uX2ZldGNoX2VuZHBvaW50IjoiaHR0cHM6Ly9mb28xMS5ibG9iLmNvcmUud2luZG93cy5uZXQvdGEtdGVzdC9mZWRlcmF0aW9uX2ZldGNoIn19fQ.iCxs1isyToYXO4jb_Aaq2qh_6Z3QAnJL1rc3XtAwgoECPt8b5s9sul97JBawvOM1ooPhnlADk79xnYux-qHUPw";
}

function getTrustAnchorSS() {
  return "eyJhbGciOiJFUzI1NiIsImtpZCI6IlVtYnVuUWwyMEFXTU9ybmlMbk52QndNa3MtV2tYTDIxdzZ1VnpmRUwxOE0ifQ.eyJpc3MiOiJodHRwczovL2ZvbzExLmJsb2IuY29yZS53aW5kb3dzLm5ldC90YS10ZXN0Iiwic3ViIjoiaHR0cHM6Ly9mb28xMS5ibG9iLmNvcmUud2luZG93cy5uZXQvcnAtdGVzdCIsImp3a3MiOnsia2V5cyI6W3sia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJCT2pidHBHQVZqTXBwZmFsLUFyLWZWTlFGWjR1UE1STWpzWUQyZ0FMTXJJIiwieSI6ImJBIiwia2lkIjoiSG15ejJxX0h5d2sxYkVXd3JmeU9uTVF6ZmZpTGQ0OGN1blBwVUttSENVVSJ9XX0sImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxODAwMDAwMDAwfQ.hF34UqyJ-2625VrbNzygorUJQkKxizNca1aaj_uA3mC4CC5bMusqWJ5d_bUxcotbdW9F85VfBI9CaGJsOhSqgg";
}

function getEC() {
  return "eyJhbGciOiJFUzI1NiIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0Iiwia2lkIjoiNUxxcGd0U3phMWREaGZmZiJ9.eyJpc3MiOiJodHRwczovL2ZvbzExLmJsb2IuY29yZS53aW5kb3dzLm5ldC9ycC10ZXN0Iiwic3ViIjoiaHR0cHM6Ly9mb28xMS5ibG9iLmNvcmUud2luZG93cy5uZXQvcnAtdGVzdCIsImF1dGhvcml0eV9oaW50cyI6WyJodHRwczovL2ZvbzExLmJsb2IuY29yZS53aW5kb3dzLm5ldC90YS10ZXN0Il0sImp3a3MiOnsia2V5cyI6W3sia3R5IjoiRUMiLCJ4IjoiZ0VLcmNjaU1yUkJCal9HQlpJMFFvbHZRM3NSOWVoZ0lubi15aFJMOGhJOCIsInkiOiJHd1ZOWXU5dUR0U29HX0ZZU1NLeGhoNHIxaXFYaldKb0VYZ3NwakIxaVVjIiwiY3J2IjoiUC0yNTYiLCJraWQiOiI1THFwZ3RTemExZERoZmZmIn1dfSwibWV0YWRhdGEiOnsiZmVkZXJhdGlvbl9lbnRpdHkiOnsiaG9tZXBhZ2VfdXJpIjoiaHR0cHM6Ly9pb2FwcC5pdC8iLCJvcmdhbml6YXRpb25fbmFtZSI6IkNvbXVuZSBkaSBTaWx2aWEiLCJjb250YWN0cyI6WyJmb29AZm9vLmZvbyJdLCJwb2xpY3lfdXJpIjoiaHR0cHM6Ly9pb2FwcC5pdC9pbmZvcm1hdGl2YS1wcml2YWN5IiwibG9nb191cmkiOiJodHRwczovL2lvYXBwLml0LyJ9LCJvcGVuaWRfY3JlZGVudGlhbF92ZXJpZmllciI6eyJhcHBsaWNhdGlvbl90eXBlIjoid2ViIiwiY2xpZW50X2lkIjoiaHR0cHM6Ly9mb28xMS5ibG9iLmNvcmUud2luZG93cy5uZXQvcnAtdGVzdCIsImNsaWVudF9uYW1lIjoiQ29tdW5lIGRpIFNpbHZpYSIsInJlc3BvbnNlX3VyaXNfc3VwcG9ydGVkIjpbImh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9kaXJlY3RfcG9zdCJdLCJ2cF9mb3JtYXRzIjp7ImRjK3NkLWp3dCI6eyJzZC1qd3RfYWxnX3ZhbHVlcyI6WyJFUzI1NiIsIkVTMzg0IiwiRVM1MTIiXX19LCJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwieCI6Ilp2TmJpd1FZMnBVR0M2MFBhUmRWa1Z5aEVjZlVyQXZwOExFbU0tcUV1UzgiLCJ5IjoiakhldHVEM2EwMk1YV2EyV2FTS2NPdElzUHZwVUgzSE0zR3BtS3Q3TzJqYyIsImNydiI6IlAtMjU2Iiwia2lkIjoieDlWcXhKUmN4OV9VZmxiUyIsInVzZSI6ImVuYyJ9XX19fSwiaWF0IjoxNzQyMjIyMjAzLCJleHAiOjE3NzM3Nzk4MDN9.c38eoulK1uw2lbxirPx-RZGj9GonFB0ssYAwzQ_S11M6UBW-90OSmUNQttpL1M9UkpZ4EuxjB0-Y__4TRIPgfg";
}

async function createRequestObject({
  clientId,
  dcqlQuery,
  flowType,
  nonceRepository,
  privateKeyBase64,
  requestObjectRepository,
  responseUri,
  state,
}: {
  clientId: string;
  dcqlQuery: DcqlQuery;
  flowType: FlowType;
  nonceRepository: NonceRepository;
  privateKeyBase64: string;
  requestObjectRepository: RequestObjectRepository;
  responseUri: string;
  state: string;
}) {
  const privateKeyPem = Buffer.from(privateKeyBase64, "base64").toString();

  const nonce = generateNonce();

  await insertNonce(nonce)(nonceRepository);

  const payload = {
    client_id: clientId,
    dcql_query: dcqlQuery,
    iss: clientId,
    nonce,
    request_uri_method: "get",
    response_mode: "direct_post.jwt",
    response_type: "vp_token",
    response_uri: responseUri,
    state,
  };

  const requestObject = jwt.sign(payload, privateKeyPem, {
    expiresIn: "1h",
    header: {
      alg: "ES256",
      kid: "x9VqxJRcx9_UflbS",
      trust_chain: [getEC(), getTrustAnchorSS(), getTrustAnchorEC()],
      typ: "oauth-authz-req+jwt",
    },
  });

  await insertRequestObject({ flowType, id: state, jwt: requestObject })(
    requestObjectRepository,
  );

  return requestObject;
}

export const createAuthorizationRequest: {
  handler: (body: AuthorizationRequest) => (dep: {
    config: Config;
    nonceRepository: NonceRepository;
    requestObjectRepository: RequestObjectRepository;
  }) => Promise<{
    url: string;
  }>;
  path: string;
} = {
  handler:
    ({ dcqlQuery, flowType, walletAuthBaseUri }) =>
    async ({ config, nonceRepository, requestObjectRepository }) => {
      let parsedQuery: DcqlQuery.Output;
      try {
        parsedQuery = DcqlQuery.parse(dcqlQuery as DcqlQuery.Input);
        DcqlQuery.validate(parsedQuery);
      } catch {
        throw new BadRequestError("DCQL is not correct");
      }
      const state = uuid.v4();

      await createRequestObject({
        clientId: config.clientId,
        dcqlQuery: parsedQuery,
        flowType,
        nonceRepository,
        privateKeyBase64: config.authRequestPrivateKey,
        requestObjectRepository,
        responseUri: `${config.basePath}/auth/response`,
        state,
      });

      const requestUri = `${config.basePath}/auth/request/${state}`;
      const presentationParams = new URLSearchParams({
        client_id: config.clientId,
        request_uri: requestUri,
        state,
      });

      const baseUrl = new URL(walletAuthBaseUri);
      for (const [key, value] of presentationParams) {
        baseUrl.searchParams.set(key, value);
      }

      return {
        url: baseUrl.toString(),
      };
    },
  path: "/request-object",
};

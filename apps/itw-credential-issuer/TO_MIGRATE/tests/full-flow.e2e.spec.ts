import { DISABILITY_CARD_ID } from "@/domain/credentials/disability-card";
import { clientAuthenticationWalletAttestationJwt } from "@pagopa/io-wallet-oauth2";
import { beforeAll, describe, expect, test } from "vitest";

import { callbacks, config, createAttestations } from "./e2e/client";
import { E2EIssuingTestFlow, PID_CREDENTIAL_ID } from "./e2e/flow";

describe("E2E Credentials Issuing Full Flow", () => {
  let walletAttestation: string;
  let clientAttestationPoP: string;

  beforeAll(async () => {
    const attestations = await createAttestations();
    walletAttestation = attestations.walletAttestation;
    clientAttestationPoP = attestations.clientAttestationPoP;

    callbacks.clientAuthentication = clientAuthenticationWalletAttestationJwt({
      callbacks,
      config,
      walletAttestationJwt: walletAttestation,
    });
  });

  test("issuing verifiable credential with oid4vci", async () => {
    const e2e = new E2EIssuingTestFlow()
      .withClientAttestationPoP(clientAttestationPoP)
      .withWalletAttestation(walletAttestation);

    await e2e.fetchFederationMetadata();
    expect(e2e.authorizationServerMetadata).toBeDefined();
    expect(e2e.issuerMetadata).toBeDefined();

    await e2e.pushedAuthorizationRequest(PID_CREDENTIAL_ID);
    expect(e2e.requestUri).toBeDefined();

    await e2e.openid4vciAuthzRequest();
    expect(e2e.code).toBeDefined();

    await e2e.tokenRequest();
    expect(e2e.accessToken).toBeDefined();

    await e2e.fetchNonce();
    expect(e2e.nonce).toBeDefined();

    const credential = await e2e.credentialRequest(PID_CREDENTIAL_ID);
    expect(credential).toBeDefined();
  });

  test("issuing verifiable credential with oid4vp", async () => {
    const e2e = new E2EIssuingTestFlow()
      .withClientAttestationPoP(clientAttestationPoP)
      .withWalletAttestation(walletAttestation);

    await e2e.fetchFederationMetadata();
    expect(e2e.authorizationServerMetadata).toBeDefined();
    expect(e2e.issuerMetadata).toBeDefined();

    await e2e.pushedAuthorizationRequest(DISABILITY_CARD_ID);
    expect(e2e.requestUri).toBeDefined();

    await e2e.openid4vpAuthzRequest();
    expect(e2e.requestObject).toBeDefined();

    await e2e.presentationResponse();
    expect(e2e.redirectUri).toBeDefined();

    await e2e.getFormPostJwt();
    expect(e2e.code).toBeDefined();

    await e2e.tokenRequest();
    expect(e2e.accessToken).toBeDefined();

    await e2e.fetchNonce();
    expect(e2e.nonce).toBeDefined();

    const credential = await e2e.credentialRequest(DISABILITY_CARD_ID);
    expect(credential).toBeDefined();
  });
});

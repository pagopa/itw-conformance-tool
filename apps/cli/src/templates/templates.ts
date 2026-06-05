import { join } from 'node:path';

import type { ConfigType } from '@itw-conformance-tool/config';

export const configINITemplate = `[global]
; Local directory for keys, certificates, and generated data
; Default: ~/.itw-conformance-tool
data_dir = ~/.itw-conformance-tool
; Logging level: debug | info | warn | error
; Default: info
log_level = info
; Enable HTTPS for the issuer service (true | false)
; Default: false
https = false

[itw-credential-issuer]
; Authentication flow: direct | l2plus | l3
; Default: direct
auth_flow = direct
; HTTP port for the issuer service
; Default: 3000
port = 3000
; Enabled credential types: pid | mdl | badge | eaa (comma-separated)
; Default: pid,mdl,badge,eaa
credential_types = pid,mdl,badge,eaa

[rp]
; HTTP port for the itw-relying-party service
; Default: 8080
port = 8080
; RP OpenID Federation Entity ID (leaf entity)
; Example: https://rp.example.org
entity_id =
; Trust Anchor URL for Federation validation
; Override with env: ITW_CT_RP_TRUST_ANCHOR_URL
trust_anchor_url = 
; Path to the private key file (PEM or JWK) used to sign the Request Object JWT 
; Override with env: ITW_CT_RP_SIGNING_KEY_PATH
signing_key_path = ~/.itw-conformance-tool/rp/signing-key.pem
; Path to the x5c certificate chain PEM file of the RP 
; Override with env: ITW_CT_RP_X5C_CERT_PATH
x5c_cert_path = ~/.itw-conformance-tool/rp/x5c-cert.pem
`;

export function getDefaultConfigs(rootPath: string): ConfigType {
  return {
    global: {
      data_dir: join(rootPath, '.itw-conformance-tool'),
      log_level: 'info',
      https: false
    },
    'itw-credential-issuer': {
      auth_flow: 'direct',
      port: 3000,
      credential_types: 'pid,mdl,badge,eaa'
    },
    rp: {
      port: 8080,
      entity_id: '',
      trust_anchor_url: '',
      signing_key_path: join(rootPath, '.itw-conformance-tool', 'rp', 'signing-key.pem'),
      x5c_cert_path: join(rootPath, '.itw-conformance-tool', 'rp', 'x5c-cert.pem')
    }
  };
}

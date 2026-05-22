import { join } from 'node:path';

import type { ConfigType } from '@itw-conformance-tool/config';

export const configINITemplate = `[global]
; Local directory for keys, certificates, and generated data
; Default: ~/.itw-conformance-tool
data_dir = ~/.itw-conformance-tool
; Logging level: debug | info | warn | error
; Default: info
log_level = info

[itw-credential-issuer]
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
`;

export function getDefaultConfigs(rootPath: string): ConfigType {
  return {
    global: {
      data_dir: join(rootPath, '.itw-conformance-tool'),
      log_level: 'info'
    },
    'itw-credential-issuer': {
      port: 3000,
      credential_types: 'pid,mdl,badge,eaa'
    },
    rp: {
      port: 8080
    }
  };
}

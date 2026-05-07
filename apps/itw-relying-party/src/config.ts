import * as z from "zod";

const Config = z.object({
  authRequestPrivateKey: z.string(),
  authResponsePrivateKey: z.string(),
  basePath: z.string(),
  clientId: z.string(),
  storageAccountConnectionString: z.string(),
});

export type Config = z.infer<typeof Config>;

const readFromEnvironment: (
  variableName: string,
  env: NodeJS.ProcessEnv,
) => string = (variableName, env) => {
  const envVar = env[variableName];
  if (envVar === undefined) {
    throw new Error(`Missing env var ${variableName}`);
  }
  return envVar;
};

const getConfigFromEnvironment = (env: NodeJS.ProcessEnv) => ({
  authRequestPrivateKey: readFromEnvironment("authRequestPrivateKey", env),
  authResponsePrivateKey: readFromEnvironment("authResponsePrivateKey", env),
  clientId: readFromEnvironment("clientId", env),
  storageAccountConnectionString: readFromEnvironment(
    "storageAccountConnectionString",
    env,
  ),
});

export const getConfig: (env: NodeJS.ProcessEnv) => Config = (env) => {
  const config = getConfigFromEnvironment(env);
  const hostname = env.WEBSITE_HOSTNAME || "";
  const basePath =
    hostname.startsWith("http://") || hostname.startsWith("https://")
      ? hostname
      : `https://${hostname}`;
  return {
    ...config,
    basePath,
  };
};

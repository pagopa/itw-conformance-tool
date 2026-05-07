import type { PreInvocationHandler } from "@azure/functions";

import { createErrorResponse } from "@/adapters/azure/functions/errors/error";
import { type RequestAppContext, appContext } from "@/app/context";
import { getSdkConfig } from "@/domain/sdk-config";
import {
  SpecVersionError,
  resolveSpecVersionFromHeaders,
} from "@/domain/spec-version";

declare module "@azure/functions" {
  interface InvocationContext {
    app: RequestAppContext;
  }
}

export const preInvocationHandler: PreInvocationHandler = async (ctx) => {
  if (ctx.invocationContext.options.trigger.type === "httpTrigger") {
    const originalHandler = ctx.functionHandler;
    ctx.functionHandler = async (request, invocationContext) => {
      try {
        const specVersion = resolveSpecVersionFromHeaders(
          request.headers as Headers,
        );

        Object.assign(invocationContext, {
          app: {
            ...appContext,
            sdkConfig: getSdkConfig(specVersion),
          },
        });

        return originalHandler(request, invocationContext);
      } catch (err) {
        if (err instanceof SpecVersionError) {
          return createErrorResponse({
            error: "invalid_request",
            error_description: err.message,
            status: 400,
          });
        }

        throw err;
      }
    };
  }
};

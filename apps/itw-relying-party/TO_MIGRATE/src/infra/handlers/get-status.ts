import {
  RequestObjectRepository,
  deleteRequestObject,
  getRequestObject,
} from "@/request-object";

export const getStatus: {
  handler: (state: string) => (
    requestObjectRepository: RequestObjectRepository,
  ) => Promise<{
    redirect_uri: string;
    values?: Record<string, null | string>[];
  }>;
  path: string;
} = {
  handler: (state) => async (requestObjectRepository) => {
    const { redirectUri, status, values } = await getRequestObject(state)(
      requestObjectRepository,
    );

    // if authentication was successful
    if (status === "verified") {
      if (!redirectUri) {
        await deleteRequestObject(state)(requestObjectRepository); // fake TTL
        return { redirect_uri: "error.html?response_code=unexpected" };
      } else {
        return {
          redirect_uri: `${redirectUri}?response_code=success`,
          values,
        };
        // response_code=success will be in redirectUri
      }
    }
    // if the request object was rejected by the wallet
    else if (status === "rejected") {
      await deleteRequestObject(state)(requestObjectRepository); // fake TTL
      return { redirect_uri: "rejected-error.html?response_code=rejected" };
    }
    // if the authorization response was rejected
    else if (status === "denied") {
      await deleteRequestObject(state)(requestObjectRepository); // fake TTL
      return { redirect_uri: "error.html?response_code=denied" };
    }
    // if it timed out
    else if (status === "expired") {
      await deleteRequestObject(state)(requestObjectRepository); // fake TTL
      return { redirect_uri: "timeout.html?response_code=expired" };
    }
    // if authentication has not been completed yet
    else if (status === "checking") {
      return { redirect_uri: "?response_code=checking" };
    } else {
      return { redirect_uri: "?response_code=pending" };
    }
  },
  path: "/status/:state",
};

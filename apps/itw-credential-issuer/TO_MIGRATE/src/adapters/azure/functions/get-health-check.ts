import type { HttpHandler } from "@azure/functions";

export const GetHealthCheckHandler: HttpHandler = async () => ({
  body: "OK",
  status: 200,
});

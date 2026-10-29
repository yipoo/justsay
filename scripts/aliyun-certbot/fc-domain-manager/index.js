"use strict";

const FC = require("@alicloud/fc20230330");
const OpenApi = require("@alicloud/openapi-client");
const Util = require("@alicloud/tea-util");
const Stream = require("@alicloud/darabonba-stream");

exports.handler = async (_event, context) => {
  if (context.region !== "cn-beijing") throw new Error("Expected cn-beijing");
  const client = new FC.default(new OpenApi.Config({
    accessKeyId: context.credentials.accessKeyId,
    accessKeySecret: context.credentials.accessKeySecret,
    securityToken: context.credentials.securityToken,
    endpoint: `${context.accountId}.cn-beijing-internal.fc.aliyuncs.com`,
    readTimeout: 850000, connectTimeout: 30000,
  }));
  const result = await client.invokeFunctionWithOptions(
    "justsay-cert-generator",
    new FC.InvokeFunctionRequest({
      qualifier: "LATEST",
      body: Stream.default.readFromString(JSON.stringify({action: "check"})),
    }),
    new FC.InvokeFunctionHeaders({xFcInvocationType: "Sync"}),
    new Util.RuntimeOptions({}));
  if (result.headers["x-fc-error-type"]) throw new Error("JustSay renewal check failed");
  const status = JSON.parse(await Util.default.readAsString(result.body));
  if (status.region !== "cn-beijing" || status.domain !== "justsay.api.53kj.com" ||
      !["not_due", "renewed"].includes(status.status)) {
    throw new Error("Unexpected renewal result");
  }
  return status;
};

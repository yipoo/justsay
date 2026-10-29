"use strict";

const FC = require("@alicloud/fc20230330");
const OpenApi = require("@alicloud/openapi-client");
const Util = require("@alicloud/tea-util");
const Stream = require("@alicloud/darabonba-stream");
const DAY = 86400000;
const MANAGER = "justsay-cert-domain-manager";
const TRIGGER = "time-trigger";

function nextRenewal(expires, now) {
  const expiry = Date.parse(expires);
  if (!Number.isFinite(expiry)) throw new Error("Invalid certificate expiry");
  return new Date(Math.max(expiry - 5 * DAY, now + 5 * 60000));
}

function cronFor(date) {
  return [date.getUTCSeconds(), date.getUTCMinutes(), date.getUTCHours(),
    date.getUTCDate(), date.getUTCMonth() + 1, "*"].join(" ");
}

function makeClient(context) {
  return new FC.default(new OpenApi.Config({
    accessKeyId: context.credentials.accessKeyId,
    accessKeySecret: context.credentials.accessKeySecret,
    securityToken: context.credentials.securityToken,
    endpoint: `${context.accountId}.cn-beijing-internal.fc.aliyuncs.com`,
    readTimeout: 30000, connectTimeout: 10000,
  }));
}

function createHandler(clientFactory = makeClient, clock = Date.now,
  pause = ms => new Promise(resolve => setTimeout(resolve, ms))) {
  return async (_event, context) => {
    if (context.region !== "cn-beijing") throw new Error("Expected cn-beijing");
    const client = clientFactory(context);
    const started = clock();
    async function schedule(date, reason) {
      const scheduledFor = date.toISOString();
      await client.updateTriggerWithOptions(MANAGER, TRIGGER,
        new FC.UpdateTriggerRequest({body: new FC.UpdateTriggerInput({
          qualifier: "LATEST",
          triggerConfig: JSON.stringify({enable: true, cronExpression: cronFor(date),
            payload: JSON.stringify({scheduledFor, reason})}),
        })}), {}, new Util.RuntimeOptions({}));
      return scheduledFor;
    }
    async function check() {
      const result = await client.invokeFunctionWithOptions("justsay-cert-generator",
        new FC.InvokeFunctionRequest({qualifier: "LATEST",
          body: Stream.default.readFromString(JSON.stringify({action: "check"}))}),
        new FC.InvokeFunctionHeaders({xFcInvocationType: "Sync"}),
        new Util.RuntimeOptions({readTimeout: 820000, connectTimeout: 10000}));
      if (result.headers["x-fc-error-type"]) throw new Error("Issuer check failed");
      const status = JSON.parse(await Util.default.readAsString(result.body));
      if (status.region !== "cn-beijing" || status.domain !== "justsay.api.53kj.com" ||
          !["not_due", "renewed"].includes(status.status)) throw new Error("Unexpected issuer result");
      return status;
    }
    let lastError;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        // Every retry rechecks live TLS first: a completed renewal is not repeated.
        const status = await check();
        const nextRenewalAt = await schedule(nextRenewal(status.expires, clock()), "expiry");
        return {...status, nextRenewalAt};
      } catch (error) {
        lastError = error;
        // Leave enough of the 900-second function budget for a complete attempt.
        if (attempt === 2 || clock() - started > 15000) break;
        await pause((attempt + 1) * 5000);
      }
    }
    let nextRetryAt;
    try {
      nextRetryAt = await schedule(new Date(clock() + 6 * 3600000), "retry");
    } catch (error) {
      throw new Error("Renewal retry scheduling failed: " + (error.code || "unknown"));
    }
    const pending = {domain: "justsay.api.53kj.com", region: "cn-beijing",
      status: "retry_scheduled", nextRetryAt};
    console.error(JSON.stringify({...pending,
      errorCode: lastError.code || "issuer_or_verification_error"}));
    // Acknowledge the handled failure so FC does not add immediate duplicate
    // async invocations on top of our explicit six-hour retry.
    return pending;
  };
}

exports.handler = createHandler();
exports.createHandler = createHandler;
exports.nextRenewal = nextRenewal;
exports.cronFor = cronFor;

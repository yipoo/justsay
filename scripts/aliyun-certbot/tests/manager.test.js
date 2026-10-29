const test = require('node:test');
const assert = require('node:assert/strict');
const {Readable} = require('node:stream');
const manager = require('../fc-domain-manager/index.js');
const now = Date.parse('2026-10-29T03:00:00Z');
const status = {domain:'justsay.api.53kj.com',region:'cn-beijing',status:'not_due',
  expires:'2027-01-27T02:05:24Z'};
const context = {region:'cn-beijing'};
function fakeClient(failures=0) {
  const calls = [];
  let count = 0;
  return {calls, get count(){return count;},
    async invokeFunctionWithOptions() {
      count++;
      if (count <= failures) throw new Error('temporary');
      return {headers:{},body:Readable.from([Buffer.from(JSON.stringify(status))])};
    },
    async updateTriggerWithOptions(name, trigger, request) {
      calls.push({name,trigger,config:JSON.parse(request.body.triggerConfig)});
    }};
}
test('schedule is exactly five days before expiry, with UTC cron fields',()=>{
  const next=manager.nextRenewal(status.expires,now);
  assert.equal(next.toISOString(),'2027-01-22T02:05:24.000Z');
  assert.equal(manager.cronFor(next),'24 5 2 22 1 *');
});
test('a date already due is clamped to avoid a past trigger',()=>{
  assert.equal(manager.nextRenewal('2026-10-29T03:00:00Z',now).getTime(),now+300000);
});
test('one normal check schedules only the exact manager trigger',async()=>{
  const api=fakeClient();
  const result=await manager.createHandler(()=>api,()=>now,async()=>{})({},context);
  assert.equal(api.count,1);
  assert.equal(result.nextRenewalAt,'2027-01-22T02:05:24.000Z');
  assert.equal(api.calls.length,1);
  assert.equal(api.calls[0].name,'justsay-cert-domain-manager');
  assert.equal(api.calls[0].trigger,'time-trigger');
  assert.equal(JSON.parse(api.calls[0].config.payload).reason,'expiry');
});
test('transient failure retries within the same execution and then schedules once',async()=>{
  const api=fakeClient(1);
  await manager.createHandler(()=>api,()=>now,async()=>{})({},context);
  assert.equal(api.count,2);
  assert.equal(api.calls.length,1);
});
test('persistent failure schedules a six-hour retry after bounded local attempts',async()=>{
  const api=fakeClient(10);
  const result=await manager.createHandler(()=>api,()=>now,async()=>{})({},context);
  assert.equal(result.status,'retry_scheduled');
  assert.equal(api.count,3);
  const payload=JSON.parse(api.calls[0].config.payload);
  assert.equal(payload.reason,'retry');
  assert.equal(payload.scheduledFor,'2026-10-29T09:00:00.000Z');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { runAction, childEnvironment, scopedState, verifyCheckout } from '../index.mjs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

const project='00000000-0000-4000-8000-000000000001';
const runID='00000000-0000-4000-8000-000000000002';
const env={GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/main',GITHUB_REPOSITORY_ID:'12',GITHUB_REPOSITORY:'org/repo',GITHUB_RUN_ID:'30',GITHUB_RUN_ATTEMPT:'1',GITHUB_JOB:'qa',GITHUB_WORKSPACE:'/tmp/workspace',ACTIONS_ID_TOKEN_REQUEST_URL:'https://pipelines.actions.githubusercontent.com/token',ACTIONS_ID_TOKEN_REQUEST_TOKEN:'runner-secret','INPUT_PROJECT-ID':project,'INPUT_DEPLOYMENT-ID':'42','INPUT_PREVIEW-URL':'https://preview.example.com','INPUT_WAIT-TIMEOUT-SECONDS':'60'};
const response=value=>new Response(JSON.stringify(Object.hasOwn(value,'value')?value:{data:value}),{status:200});
test('verified session precedes auth and one dispatch; all runs must pass',async()=>{
 const order=[]; let calls=0;
 const result=await runAction(env,{fetch:async(url,options={})=>{
  order.push(new URL(url).pathname);
  if(url.includes('pipelines.')) return response({value:'oidc-secret'});
  if(url.endsWith('/ci/sessions'))return response({token:'ci-secret',expires_at:new Date(Date.now()+900000).toISOString(),project_id:project,origin:'https://preview.example.com',commit_sha:'a'.repeat(40),workflow_sha:'b'.repeat(40)});
  if(url.endsWith('/ci/runs')){calls++;return response({runs:[{id:runID,status:'queued'}]});}
  return response({run:{id:runID,status:'passed'}});
 },sleep:async()=>{}});
 assert.equal(result.status,'passed');assert.equal(calls,1);assert.deepEqual(order,['/token','/releasepassport/v1/ci/sessions','/releasepassport/v1/ci/runs','/releasepassport/v1/ci/runs/'+runID]);
});
test('ambiguous dispatch is never retried and response content is not exposed',async()=>{
 let dispatches=0;
 await assert.rejects(runAction(env,{fetch:async url=>{
  if(url.includes('pipelines.'))return response({value:'oidc-secret'});
  if(url.endsWith('/ci/sessions'))return response({token:'ci-secret',expires_at:new Date(Date.now()+900000).toISOString(),project_id:project,origin:'https://preview.example.com',commit_sha:'a'.repeat(40),workflow_sha:'b'.repeat(40)});
  dispatches++;throw Error('PRIVATE-CREDENTIAL');
 }}),error=>!error.message.includes('PRIVATE')&&error.message.includes('DISPATCH_UNCERTAIN'));
 assert.equal(dispatches,1);
});
test('fork/PR execution and mismatched verified origins are rejected before auth',async()=>{
 await assert.rejects(runAction({...env,GITHUB_EVENT_NAME:'pull_request'},{fetch:()=>{throw Error('must not fetch');}}),/UNTRUSTED_WORKFLOW/);
 await assert.rejects(runAction(env,{fetch:async url=>url.includes('pipelines.')?response({value:'jwt'}):response({token:'token',origin:'https://attacker.example',project_id:project,expires_at:new Date(Date.now()+900000).toISOString(),commit_sha:'a'.repeat(40),workflow_sha:'b'.repeat(40)})}),/SESSION_BINDING_INVALID/);
});
test('child process receives only explicitly selected testing secrets',()=>{
 const selected=childEnvironment({...env,RP_TEST_PASSWORD:'test-secret',GITHUB_TOKEN:'private',VISION_GATEWAY_KEY:'private',NODE_OPTIONS:'--require evil'},['RP_TEST_PASSWORD'],'https://preview.example.com');
 assert.equal(selected.RP_TEST_PASSWORD,'test-secret');assert.equal(selected.GITHUB_TOKEN,undefined);assert.equal(selected.ACTIONS_ID_TOKEN_REQUEST_TOKEN,undefined);assert.equal(selected.VISION_GATEWAY_KEY,undefined);assert.equal(selected.NODE_OPTIONS,undefined);
 assert.throws(()=>childEnvironment(env,['GITHUB_TOKEN'],'https://preview.example.com'),/AUTH_ENV_INVALID/);
});
test('state export retains only exact-origin secure cookies/local storage',()=>{
 const state=scopedState({cookies:[{name:'ok',value:'v',domain:'preview.example.com',secure:true,httpOnly:true,path:'/',expires:-1,sameSite:'Lax'},{name:'foreign',domain:'google.com',secure:true},{name:'broad',domain:'.example.com',secure:true}],origins:[{origin:'https://preview.example.com',localStorage:[{name:'x',value:'y'}],indexedDB:[{}]},{origin:'https://foreign.example',localStorage:[]}]},'https://preview.example.com');
 assert.equal(state.cookies.length,1);assert.deepEqual(state.origins,[{origin:'https://preview.example.com',localStorage:[{name:'x',value:'y'}]}]);
});
test('authentication requires an unchanged trusted workflow checkout',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'rp-action-checkout-'));
 try{
  const git=(...args)=>execFileSync('git',args,{cwd:dir,encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
  git('init','--initial-branch=main');await writeFile(join(dir,'auth.mjs'),'export default async()=>{}');git('add','auth.mjs');git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-m','fixture');const sha=git('rev-parse','HEAD');
  await verifyCheckout(dir,sha,'auth.mjs');await assert.rejects(verifyCheckout(dir,'b'.repeat(40),'auth.mjs'),/UNTRUSTED_CHECKOUT/);
  await writeFile(join(dir,'auth.mjs'),'console.log("unsafe")');await assert.rejects(verifyCheckout(dir,sha,'auth.mjs'),/UNTRUSTED_CHECKOUT/);
 }finally{await rm(dir,{recursive:true,force:true});}
});
test('a failed or uncertain mission never produces a passing action',async()=>{
 let dispatches=0;
 await assert.rejects(runAction(env,{fetch:async url=>{
  if(url.includes('pipelines.'))return response({value:'jwt'});
  if(url.endsWith('/ci/sessions'))return response({token:'ci-secret',expires_at:new Date(Date.now()+900000).toISOString(),project_id:project,origin:'https://preview.example.com',commit_sha:'a'.repeat(40),workflow_sha:'b'.repeat(40)});
  if(url.endsWith('/ci/runs')){dispatches++;return response({runs:[{id:runID,status:'queued'}]});}
  return response({run:{id:runID,status:'inconclusive',reason_code:'MODEL_USAGE_UNKNOWN'}});
 }}),/QA_NOT_PASSED/);assert.equal(dispatches,1);
});
test('authentication/upload failures never dispatch a possibly paid QA run',async()=>{
 let calls=0;let auth=0;
 await assert.rejects(runAction({...env,'INPUT_AUTH-SETUP-SCRIPT':'auth.mjs'},{authenticate:async()=>{auth++;return {cookies:[],origins:[]};},fetch:async url=>{
  if(url.includes('pipelines.'))return response({value:'jwt'});
  if(url.endsWith('/ci/sessions'))return response({token:'ci-secret',expires_at:new Date(Date.now()+900000).toISOString(),project_id:project,origin:'https://preview.example.com',commit_sha:'a'.repeat(40),workflow_sha:'b'.repeat(40)});
  if(url.endsWith('/ci/auth-state'))throw Error('PRIVATE-CREDENTIAL');calls++;return response({runs:[]});
 }}),/AUTH_UPLOAD_UNCERTAIN/);assert.equal(auth,1);assert.equal(calls,0);
});

test('trusted workflow_run can resolve its upstream deployment SHA without a caller URL',async()=>{
 let body;const selected={...env,GITHUB_EVENT_NAME:'workflow_run','INPUT_DEPLOYMENT-ID':'','INPUT_PREVIEW-URL':'','INPUT_DEPLOYMENT-SHA':'c'.repeat(40)};
 const result=await runAction(selected,{fetch:async(url,options={})=>{
  if(url.includes('pipelines.'))return response({value:'jwt'});
  if(url.endsWith('/ci/sessions')){body=JSON.parse(options.body);return response({token:'token',expires_at:new Date(Date.now()+900000).toISOString(),project_id:project,origin:'https://preview.example.com',commit_sha:'c'.repeat(40),workflow_sha:'b'.repeat(40)});}
  if(url.endsWith('/ci/runs'))return response({runs:[{id:runID}]});
  return response({run:{id:runID,status:'passed'}});
 }});assert.equal(result.status,'passed');assert.equal(body.deployment_sha,'c'.repeat(40));assert.equal(body.preview_url,undefined);assert.equal(body.deployment_id,undefined);
});

for(const mode of ['skip-worktree','assume-unchanged'])test(`checkout byte verification rejects ${mode} hidden auth and imported helper changes`,async()=>{
 const dir=await mkdtemp(join(tmpdir(),'rp-action-hidden-'));
 try{
  const git=(...args)=>execFileSync('git',args,{cwd:dir,encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
  git('init','--initial-branch=main');
  const auth='import setup from "./helper.mjs"; export default setup;';
  await writeFile(join(dir,'auth.mjs'),auth);await writeFile(join(dir,'helper.mjs'),'export default async()=>{}');
  git('add','.');git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-m','fixture');const sha=git('rev-parse','HEAD');
  await verifyCheckout(dir,sha,'auth.mjs');
  git('update-index','--'+mode,'auth.mjs','helper.mjs');
  await writeFile(join(dir,'auth.mjs'),'export default async()=>{throw Error("changed")}');
  await assert.rejects(verifyCheckout(dir,sha,'auth.mjs'),/UNTRUSTED_CHECKOUT/);
  await writeFile(join(dir,'auth.mjs'),auth);await writeFile(join(dir,'helper.mjs'),'export default async()=>{throw Error("changed helper")}');
  await assert.rejects(verifyCheckout(dir,sha,'auth.mjs'),/UNTRUSTED_CHECKOUT/);
 }finally{await rm(dir,{recursive:true,force:true});}
});
for(const mode of ['delayed-body','ten-run-batch'])test(`polling enforces one-second deadline during ${mode}`,async()=>{
 const runs=Array.from({length:mode==='ten-run-batch'?10:1},(_,i)=>({id:'00000000-0000-4000-8000-'+String(i+10).padStart(12,'0')}));
 let observedSignal;
 await assert.rejects(runAction({...env,'INPUT_WAIT-TIMEOUT-SECONDS':'1'},{fetch:async(url,options={})=>{
  if(url.includes('pipelines.'))return response({value:'jwt'});
  if(url.endsWith('/ci/sessions'))return response({token:'token',expires_at:new Date(Date.now()+900000).toISOString(),project_id:project,origin:'https://preview.example.com',commit_sha:'a'.repeat(40),workflow_sha:'b'.repeat(40)});
  if(url.endsWith('/ci/runs'))return response({runs});
  observedSignal=options.signal;
  const id=url.split('/').at(-1);
  return {ok:true,text:async()=>{await new Promise(resolve=>setTimeout(resolve,mode==='ten-run-batch'?125:1200));return JSON.stringify({data:{run:{id,status:'passed'}}});}};
 }}),/WAIT_EXPIRED_CHECK_RUN_HISTORY/);
 assert.equal(observedSignal.aborted,true);
});

test('attestation ignores local Git replacement objects',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'rp-action-replace-'));
 try{
  const git=(...args)=>execFileSync('git',args,{cwd:dir,encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
  git('init','--initial-branch=main');
  await writeFile(join(dir,'auth.mjs'),'export default async()=>{}');git('add','.');
  const commit=()=>git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-m','fixture');
  commit();const trusted=git('rev-parse','HEAD');
  await writeFile(join(dir,'auth.mjs'),'export default async()=>{throw Error("replacement")}');git('add','.');commit();const replacement=git('rev-parse','HEAD');
  git('reset','--soft',trusted);git('replace',trusted,replacement);
  assert.equal(git('rev-parse','HEAD'),trusted);
  await assert.rejects(verifyCheckout(dir,trusted,'auth.mjs'),/UNTRUSTED_CHECKOUT/);
  git('replace','-d',trusted);git('reset','--hard',trusted);
  await verifyCheckout(dir,trusted,'auth.mjs');
 }finally{await rm(dir,{recursive:true,force:true});}
});

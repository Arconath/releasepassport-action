import { createHash } from 'node:crypto';
import { mkdtemp, realpath, readFile, rm, chmod, stat, lstat, appendFile } from 'node:fs/promises';
import { resolve, relative, isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, execFileSync } from 'node:child_process';

const API='https://api.arconath.com/releasepassport/v1';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const fail=code=>{throw Error(code);};
const input=(env,name)=>env['INPUT_'+name.toUpperCase().replaceAll(' ','_')]?.trim()||'';
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function originURL(value){
 let url;try{url=new URL(value);}catch{fail('PREVIEW_URL_INVALID');}
 if(url.protocol!=='https:'||url.username||url.password||url.hash||url.hostname==='localhost'||url.hostname.endsWith('.localhost')||url.hostname.endsWith('.local')||url.hostname.includes(':')||/^\d+(\.\d+){3}$/.test(url.hostname))fail('PREVIEW_URL_INVALID');
 return url;
}
export function childEnvironment(env,names,origin){
 const out={RP_PREVIEW_URL:origin};
 for(const key of ['PATH','HOME','TMPDIR','TEMP','TMP','SYSTEMROOT','WINDIR','PLAYWRIGHT_BROWSERS_PATH'])if(env[key])out[key]=env[key];
 for(const key of names){if(!/^RP_TEST_[A-Z0-9_]+$/.test(key)||!env[key])fail('AUTH_ENV_INVALID');out[key]=env[key];}
 return out;
}
export function scopedState(raw,origin){
 const host=new URL(origin).hostname;
 if(!raw||!Array.isArray(raw.cookies)||!Array.isArray(raw.origins))fail('AUTH_STATE_INVALID');
 const state={cookies:raw.cookies.filter(c=>c.domain===host&&c.secure===true).map(c=>({name:c.name,value:c.value,domain:c.domain,path:c.path,expires:c.expires,httpOnly:c.httpOnly,secure:c.secure,sameSite:c.sameSite})),origins:raw.origins.filter(o=>o.origin===origin).map(o=>({origin:o.origin,localStorage:o.localStorage}))};
 if(state.cookies.length>100||state.origins.length>1||(!state.cookies.length&&!state.origins.some(o=>o.localStorage?.length))||Buffer.byteLength(JSON.stringify(state))>256*1024)fail('AUTH_STATE_INVALID');
 return state;
}
function checkDeadline(deadline){if(Date.now()>=deadline)fail('WAIT_EXPIRED_CHECK_RUN_HISTORY');}
async function jsonRequest(fetcher,url,options={},code='REQUEST_FAILED',deadline=Infinity){
 try{
  checkDeadline(deadline);
  const response=await fetcher(url,{...options,redirect:'error',signal:AbortSignal.timeout(Math.min(20000,Math.max(1,deadline-Date.now())))});
  checkDeadline(deadline);
  const text=await response.text();checkDeadline(deadline);
  if(text.length>1024*1024||!response.ok)fail(code);
  const parsed=JSON.parse(text);checkDeadline(deadline);
  return url.startsWith(API+'/')?parsed.data:parsed;
 }catch{checkDeadline(deadline);fail(code);}
}
export async function verifyCheckout(workspace,sha,script){
 try{
  if(!/^[0-9a-f]{40}$/i.test(sha||''))fail('UNTRUSTED_CHECKOUT');
  workspace=await realpath(workspace);
  const options={cwd:workspace,encoding:'utf8',stdio:['ignore','pipe','pipe'],timeout:10000,maxBuffer:16*1024*1024,env:{PATH:process.env.PATH,HOME:process.env.HOME,GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_NO_REPLACE_OBJECTS:'1'}};
  if(execFileSync('git',['--no-replace-objects','rev-parse','HEAD'],options).trim().toLowerCase()!==sha.toLowerCase())fail('UNTRUSTED_CHECKOUT');
  // Read the attested tree, never index flags: skip-worktree and assume-unchanged
  // can hide edits from git diff, including a tracked helper imported by auth.
  const tree=execFileSync('git',['--no-replace-objects','ls-tree','-r','-z',sha],options).split('\0').filter(Boolean);
  let foundScript=false;
  for(const entry of tree){
   const match=/^(100644|100755) blob ([0-9a-f]{40})\t([\s\S]+)$/.exec(entry);
   if(!match)fail('UNTRUSTED_CHECKOUT'); // Symlinks and submodules are unsupported.
   const [, ,blob,path]=match;
   const file=resolve(workspace,path),local=relative(workspace,file);
   if(isAbsolute(local)||local==='..'||local.startsWith('../')||path.split('/').at(-1)==='.gitattributes'||!(await lstat(file)).isFile()||await realpath(file)!==file)fail('UNTRUSTED_CHECKOUT');
   const bytes=await readFile(file);
   const actual=createHash('sha1').update('blob '+bytes.length+'\0').update(bytes).digest('hex');
   if(actual!==blob)fail('UNTRUSTED_CHECKOUT');
   if(path===script)foundScript=true;
  }
  if(!foundScript)fail('UNTRUSTED_CHECKOUT');
 }catch{fail('UNTRUSTED_CHECKOUT');}
}
export async function authenticate(env,script,origin,workflowSHA){
 const workspace=await realpath(env.GITHUB_WORKSPACE||'');
 const scriptPath=await realpath(resolve(workspace,script));
 const local=relative(workspace,scriptPath);
 if(isAbsolute(local)||local==='..'||local.startsWith('../')||!scriptPath.endsWith('.mjs')||!(await stat(scriptPath)).isFile())fail('AUTH_SCRIPT_INVALID');
 await verifyCheckout(workspace,workflowSHA,local);
 const tempRoot=await realpath(env.RUNNER_TEMP||'');
 const dir=await mkdtemp(join(tempRoot,'releasepassport-auth-'));await chmod(dir,0o700);
 const path=join(dir,'state.json');
 try{
  const names=input(env,'auth-env').split(/[\s,]+/).filter(Boolean);
  const childEnv=childEnvironment(env,names,origin);
  await new Promise((resolve,reject)=>{
   const child=spawn(process.execPath,[fileURLToPath(new URL('./auth-child.mjs',import.meta.url)),scriptPath,path,origin],{cwd:workspace,env:childEnv,stdio:['ignore','pipe','pipe'],timeout:120000,killSignal:'SIGKILL'});
   let bytes=0;const consume=data=>{bytes+=data.length;if(bytes>65536)child.kill('SIGKILL');};child.stdout.on('data',consume);child.stderr.on('data',consume);
   child.once('error',()=>reject(Error('AUTH_SETUP_FAILED')));child.once('close',code=>code===0&&bytes<=65536?resolve():reject(Error('AUTH_SETUP_FAILED')));
  });
  if(await realpath(path)!==path||(await stat(path)).size>256*1024)fail('AUTH_STATE_INVALID');
  return scopedState(JSON.parse(await readFile(path,'utf8')),origin);
 }catch(error){fail(['AUTH_ENV_INVALID','AUTH_SCRIPT_INVALID','AUTH_STATE_INVALID'].includes(error.message)?error.message:'AUTH_SETUP_FAILED');}
 finally{await rm(dir,{recursive:true,force:true});}
}
export async function runAction(env=process.env,hooks={}){
 const fetcher=hooks.fetch||fetch;
 if(!['push','workflow_dispatch','workflow_run','deployment_status'].includes(env.GITHUB_EVENT_NAME)||!env.GITHUB_REF?.startsWith('refs/heads/')||!env.GITHUB_REPOSITORY_ID||!env.GITHUB_RUN_ID||!env.GITHUB_RUN_ATTEMPT||!env.GITHUB_JOB)fail('UNTRUSTED_WORKFLOW');
 const project=input(env,'project-id'),deployment=input(env,'deployment-id'),deploymentSHA=input(env,'deployment-sha'),preview=input(env,'preview-url')?originURL(input(env,'preview-url')):null;
 if(!UUID.test(project)||Boolean(deployment)===Boolean(deploymentSHA)||(deployment&&(!/^\d+$/.test(deployment)||!Number.isSafeInteger(Number(deployment))||Number(deployment)<1))||(deploymentSHA&&!/^[0-9a-f]{40}$/i.test(deploymentSHA)))fail('ACTION_INPUT_INVALID');
 const timeout=Number(input(env,'wait-timeout-seconds')||900);if(!Number.isInteger(timeout)||timeout<1||timeout>900)fail('ACTION_INPUT_INVALID');
 const ids=input(env,'mission-ids').split(/[\s,]+/).filter(Boolean);if(ids.length>10||ids.some(id=>!UUID.test(id))||new Set(ids).size!==ids.length)fail('ACTION_INPUT_INVALID');
 let oidcURL;try{oidcURL=new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);}catch{fail('OIDC_UNAVAILABLE');}
 if(oidcURL.protocol!=='https:'||!oidcURL.hostname.endsWith('.actions.githubusercontent.com')||oidcURL.username||oidcURL.password||!env.ACTIONS_ID_TOKEN_REQUEST_TOKEN)fail('OIDC_UNAVAILABLE');
 oidcURL.searchParams.set('audience',API);
 const jwt=await jsonRequest(fetcher,oidcURL.href,{headers:{Authorization:'Bearer '+env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}},'OIDC_UNAVAILABLE');if(!jwt||typeof jwt.value!=='string'||!jwt.value)fail('OIDC_UNAVAILABLE');
 const key=createHash('sha256').update([env.GITHUB_REPOSITORY_ID,env.GITHUB_RUN_ID,env.GITHUB_RUN_ATTEMPT,env.GITHUB_JOB,project,deployment||deploymentSHA].join(':')).digest('hex');
 const session=await jsonRequest(fetcher,API+'/ci/sessions',{method:'POST',headers:{Authorization:'Bearer '+jwt.value,'Content-Type':'application/json'},body:JSON.stringify({project_id:project,...(deployment?{deployment_id:Number(deployment)}:{deployment_sha:deploymentSHA}),...(preview?{preview_url:preview.href}:{}),idempotency_key:key})},'SESSION_EXCHANGE_FAILED');
 if(!session||typeof session.token!=='string'||!session.token||session.project_id!==project||(preview&&session.origin!==preview.origin)||!/^([0-9a-f]{40}|[0-9a-f]{64})$/i.test(session.commit_sha||'')||!/^[0-9a-f]{40}$/i.test(session.workflow_sha||'')||!(Date.parse(session.expires_at)>Date.now()))fail('SESSION_BINDING_INVALID');
 if(originURL(session.origin).origin!==session.origin)fail('SESSION_BINDING_INVALID');
 const headers={Authorization:'Bearer '+session.token,'Content-Type':'application/json'};
 if(input(env,'auth-setup-script')){
  const state=await (hooks.authenticate||authenticate)(env,input(env,'auth-setup-script'),session.origin,session.workflow_sha);
  await jsonRequest(fetcher,API+'/ci/auth-state',{method:'POST',headers,body:JSON.stringify({storage_state:state,expires_at:new Date(Math.min(Date.now()+3600000,Date.parse(session.expires_at))).toISOString()})},'AUTH_UPLOAD_UNCERTAIN');
 }
 const admitted=await jsonRequest(fetcher,API+'/ci/runs',{method:'POST',headers,body:JSON.stringify({...(ids.length?{mission_ids:ids}:{}),idempotency_key:key})},'DISPATCH_UNCERTAIN_CHECK_RUN_HISTORY');
 if(!admitted||!Array.isArray(admitted.runs)||!admitted.runs.length||admitted.runs.length>10||admitted.runs.some(r=>!r||!UUID.test(r.id))||new Set(admitted.runs.map(r=>r.id)).size!==admitted.runs.length)fail('DISPATCH_UNCERTAIN_CHECK_RUN_HISTORY');
 const deadline=Math.min(Date.now()+timeout*1000,Date.parse(session.expires_at));
 const pending=new Set(admitted.runs.map(r=>r.id));const results=[];
 while(pending.size){
  checkDeadline(deadline);
  for(const id of pending){
   checkDeadline(deadline);
   const detail=await jsonRequest(fetcher,API+'/ci/runs/'+id,{headers},'RUN_STATUS_UNAVAILABLE',deadline);
   checkDeadline(deadline);
   if(detail?.run?.id!==id||!['queued','running','passed','failed','inconclusive','error','cancelled'].includes(detail.run.status))fail('RUN_STATUS_INVALID');
   if(!['queued','running'].includes(detail.run.status)){results.push(detail.run);pending.delete(id);}
  }
  if(pending.size)await (hooks.sleep||sleep)(Math.min(2000,Math.max(1,deadline-Date.now())));
 }
 checkDeadline(deadline);
 if(results.some(r=>r.status!=='passed'))fail('QA_NOT_PASSED');
 return {status:'passed',run_ids:results.map(r=>r.id)};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const result=await runAction();if(process.env.GITHUB_OUTPUT)await appendFile(process.env.GITHUB_OUTPUT,'status=passed\nrun-ids='+result.run_ids.join(',')+'\n');console.log('ReleasePassport QA passed.');}
 catch(error){console.error('ReleasePassport: '+(/^[A-Z_]+$/.test(error.message)?error.message:'ACTION_FAILED'));process.exitCode=1;}
}

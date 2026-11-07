import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, symlink, realpath, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { authenticate } from '../index.mjs';

test('fresh Chromium login exports scoped state, strips runtime keys, suppresses logs and cleans generated session',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'rp-auth-browser-'));
 try{
  const localModules=fileURLToPath(new URL('../node_modules',import.meta.url));
  const productModules=fileURLToPath(new URL('../../../runner/node_modules',import.meta.url));
  await symlink(await realpath(existsSync(localModules)?localModules:productModules),join(dir,'node_modules'),'dir');
  const script=`export default async function({page,baseURL}) {
   if(process.env.GITHUB_TOKEN || process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || process.env.VISION_GATEWAY_KEY) throw Error('environment leak');
   console.log(process.env.RP_TEST_PASSWORD);
   await page.route('**/*',async route=>{
    const url=new URL(route.request().url());
    if(url.pathname==='/session')return route.fulfill({status:200,headers:{'Content-Type':'application/json','Set-Cookie':'session=SYNTHETIC; Secure; HttpOnly; Path=/; SameSite=Lax'},body:'{}'});
    return route.fulfill({status:200,contentType:'text/html',body:'<input id="password" type="password"><button>Sign in</button><script>document.querySelector("button").onclick=async()=>{await fetch("/session",{method:"POST"});localStorage.setItem("signed-in","yes");document.body.dataset.ready="yes"}</script>'});
   });
   await page.goto(baseURL+'/login');await page.locator('#password').fill(process.env.RP_TEST_PASSWORD);await page.getByRole('button',{name:'Sign in'}).click();await page.locator('body[data-ready="yes"]').waitFor();
  }`;
  await writeFile(join(dir,'auth.mjs'),script);
  const git=(...args)=>execFileSync('git',args,{cwd:dir,encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
  git('init','--initial-branch=main');git('add','auth.mjs');git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-m','fixture');
  const state=await authenticate({...process.env,GITHUB_WORKSPACE:dir,RUNNER_TEMP:dir,GITHUB_TOKEN:'PRIVATE',ACTIONS_ID_TOKEN_REQUEST_TOKEN:'PRIVATE',VISION_GATEWAY_KEY:'PRIVATE',RP_TEST_PASSWORD:'SYNTHETIC-PASSWORD','INPUT_AUTH-ENV':'RP_TEST_PASSWORD'},'auth.mjs','https://preview.example.com',git('rev-parse','HEAD'));
  assert.equal(state.cookies[0].name,'session');assert.equal(state.cookies[0].httpOnly,true);assert.equal(state.cookies[0].secure,true);assert.equal(state.origins[0].localStorage[0].value,'yes');assert.equal((await readdir(dir)).some(name=>name.startsWith('releasepassport-auth-')),false);
 }finally{await rm(dir,{recursive:true,force:true});}
});

import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { writeFile } from 'node:fs/promises';
import { scopedState } from './index.mjs';

const [script,path,origin]=process.argv.slice(2);
let browser;
try{
 const require=createRequire(script);let engine;
 try{engine=require('playwright');}catch{engine=require('@playwright/test');}
 const setup=await import(pathToFileURL(script).href);
 if(typeof setup.default!=='function')throw Error('AUTH_SCRIPT_INVALID');
 browser=await engine.chromium.launch({headless:true});
 const context=await browser.newContext({serviceWorkers:'block',acceptDownloads:false});
 const page=await context.newPage();page.setDefaultTimeout(15000);page.setDefaultNavigationTimeout(30000);
 await setup.default({page,baseURL:origin});
 if(new URL(page.url()).origin!==origin)throw Error('AUTH_ORIGIN_INVALID');
 const state=scopedState(await context.storageState(),origin);
 await writeFile(path,JSON.stringify(state),{mode:0o600,flag:'wx'});
}catch{process.exitCode=1;}
finally{await browser?.close().catch(()=>{});}

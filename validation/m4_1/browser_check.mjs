/** Real Streamlit/Chromium smoke test; all service data is explicitly synthetic. */
import {createRequire} from 'node:module';
import {spawn} from 'node:child_process';
import {writeFile,mkdir,readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import assert from 'node:assert/strict';
const here=path.dirname(fileURLToPath(import.meta.url)), repo=path.resolve(here,'../..');
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE || 'playwright');
let args=[];
if(process.env.CHROMIUM_ARGS_MODULE) args=(await import(process.env.CHROMIUM_ARGS_MODULE)).default.args;
const port=process.env.M4_TEST_PORT || '8765', url=`http://127.0.0.1:${port}`;
const server=spawn(process.env.PYTHON || 'python',['-m','streamlit','run',path.join(here,'siem_fixture.py'),'--server.port',port,'--server.address','127.0.0.1','--server.headless','true'],{cwd:repo,env:{...process.env,PYTHONPATH:path.join(repo,'src')}});
let serverLog=''; server.stdout.on('data',d=>serverLog+=d);server.stderr.on('data',d=>serverLog+=d);
const checks=[], errors=[];let browser;
try {
 for(let n=0;n<100;n++){try{if((await fetch(`${url}/_stcore/health`)).ok)break;}catch{}await new Promise(r=>setTimeout(r,200));}
 browser=await chromium.launch({headless:true,args,executablePath:process.env.M4_BROWSER_EXECUTABLE || undefined});
 const page=await browser.newPage({viewport:{width:1440,height:1000}});
 page.on('pageerror',e=>errors.push(e.message));
 await page.goto(url);const root=page.locator('#monitoring-workbench');await root.waitFor({timeout:45000});
 assert.equal(await root.locator('tbody tr').count(),7);checks.push('Actual route and Components v2: seven fixture rows');
 assert.equal(await root.locator('.summary-item').nth(1).innerText(),'2\nMonitoring verified');checks.push('Two verified fixtures, including zero-alert collection health');
 await root.getByRole('button',{name:'Inspect FIXTURE-03',exact:true}).click();
 assert.match(await root.locator('.inspector').innerText(),/telemetry unverified/);checks.push('Active-only agent stays telemetry unverified');
 await page.keyboard.press('Escape');assert.equal(await root.locator('.inspector').isVisible(),false);checks.push('Escape closes inspector');
 await root.getByRole('button',{name:'Inspect FIXTURE-02',exact:true}).click();
 await root.getByRole('button',{name:'Provenance',exact:true}).click();
 assert.match(await root.locator('.inspector').innerText(),/collection_health/);checks.push('Quiet-agent health provenance visible');
 await root.getByRole('button',{name:'Scope',exact:true}).click();
 assert.match(await root.locator('.inspector').innerText(),/approved|scope/i);checks.push('Scope limits visible');
 const shotDir=process.env.M4_SCREENSHOT_DIR;
 if(shotDir){await mkdir(shotDir,{recursive:true});await page.screenshot({path:path.join(shotDir,'desktop.png'),fullPage:true});}
 await page.keyboard.press('Escape');
 const search=root.getByRole('searchbox');await search.fill('FIXTURE-02');assert.equal(await root.locator('tbody tr').count(),1);
 await search.fill('no-match');assert.match(await root.innerText(),/No assets match/);await search.fill('');checks.push('Search, empty search and reset');
 await root.getByRole('combobox').selectOption('active_unverified');assert.equal(await root.locator('tbody tr').count(),1);await root.getByRole('combobox').selectOption('');checks.push('State filter');
 await page.getByRole('button',{name:/Wazuh actions/}).click();
 assert.equal(await page.getByRole('button',{name:'Configure integration',exact:true}).isDisabled(),true);
 assert.equal(await page.getByRole('button',{name:'Collect Wazuh evidence',exact:true}).isDisabled(),true);
 await page.getByRole('button',{name:'Test connection',exact:true}).click();
 await page.getByText('Connection test succeeded.',{exact:false}).waitFor();
 if(!await page.getByRole('button',{name:'Collect Wazuh evidence',exact:true}).isVisible()) await page.getByRole('button',{name:/Wazuh actions/}).click();
 await page.getByRole('button',{name:'Collect Wazuh evidence',exact:true}).click();
 await page.getByText('Collection succeeded. 2 canonical evidence records available.',{exact:true}).waitFor();checks.push('Native connection/collection action transitions with synthetic service');
 const downloadPromise=page.waitForEvent('download');await page.getByRole('button',{name:'Export Wazuh monitoring CSV',exact:true}).click();const download=await downloadPromise;assert.match(download.suggestedFilename(),/\.csv$/);checks.push('Existing CSV download reachable');
 const excelPromise=page.waitForEvent('download');await page.getByRole('button',{name:'Export Wazuh evidence Excel',exact:true}).click();const excel=await excelPromise;assert.match(excel.suggestedFilename(),/\.xlsx$/);assert.equal((await readFile(await excel.path())).subarray(0,2).toString(),'PK');checks.push('Existing Excel workbook download reachable');
 await page.setViewportSize({width:390,height:844});
 await root.getByRole('button',{name:'Inspect FIXTURE-02',exact:true}).click();
 assert.ok(await root.locator('.inspector').isVisible());
 const box=await root.boundingBox();assert.ok(box.width<=390);
 const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth);assert.equal(overflow,false);checks.push('390px view: inspector usable, no document horizontal overflow');
 if(shotDir){await page.screenshot({path:path.join(shotDir,'mobile.png'),fullPage:true});await root.getByRole('button',{name:'Close monitoring inspector',exact:true}).click();await page.locator('[data-testid=stMain]').evaluate(el=>el.scrollTo(0,0));await page.screenshot({path:path.join(shotDir,'mobile-table.png'),fullPage:true});}
 assert.equal(await page.locator('[data-testid="stException"]').count(),0);assert.deepEqual(errors,[]);
 await writeFile(path.join(here,'browser-results.json'),JSON.stringify({result:'passed',browser:await browser.version(),viewportWidths:[1440,390],checks,boundary:'Actual Streamlit route and Components v2; synthetic services only. Not live Wazuh, authentication or PostgreSQL acceptance.'},null,2)+'\n');
 console.log(JSON.stringify({result:'passed',checks},null,2));
} catch(error){await writeFile(path.join(here,'browser-results.json'),JSON.stringify({result:'failed',checks,error:String(error)},null,2)+'\n');console.error(error);console.error(serverLog);process.exitCode=1;} finally {if(browser)await browser.close();server.kill('SIGTERM');await writeFile(path.join(here,'browser-server.log'),serverLog);}

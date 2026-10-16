// Uses an installed TypeScript compiler, without pretending to compile Vue templates or resolve npm packages.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const ts=require(process.env.TYPESCRIPT_PATH||path.resolve(__dirname,'../frontend/node_modules/typescript'));
const root=path.resolve(__dirname,'../frontend/src');let files=0;
function walk(dir){for(const entry of fs.readdirSync(dir,{withFileTypes:true})){const full=path.join(dir,entry.name);if(entry.isDirectory()){walk(full);continue;}if(!/\.(ts|vue)$/.test(full)||/\.d\.ts$/.test(full))continue;let source=fs.readFileSync(full,'utf8');if(full.endsWith('.vue')){const match=source.match(/<script[^>]*>([\s\S]*?)<\/script>/);source=match?match[1]:'';}
 const out=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext,isolatedModules:true},reportDiagnostics:true,fileName:full+'.ts'});
 const errors=out.diagnostics.filter(d=>d.category===ts.DiagnosticCategory.Error);if(errors.length){console.error(ts.formatDiagnosticsWithColorAndContext(errors,{getCanonicalFileName:f=>f,getCurrentDirectory:()=>root,getNewLine:()=> '\n'}));process.exit(1);}files++;}}
walk(root);
const source=fs.readFileSync(path.join(root,'format.ts'),'utf8');const compiled=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText;const output={};new Function('exports',compiled)(output);
assert.equal(output.label('smtp_accepted'),'SMTP 已接受');assert.equal(output.label('queued'),'已排队');assert.equal(output.tone('unknown'),'warn');assert.equal(output.bytes(null),'未采集');assert.equal(output.bytes(1073741824),'1.0 GiB');assert.equal(output.bytes(-1),'未知');assert.equal(output.time('invalid'),'未知');assert.equal(output.time(null),'未记录');assert.equal(output.display(false),'否');assert.equal(output.display(null),'—');
console.log(`PASS: TypeScript syntactic transpilation of ${files} script files; 10 executed presentation assertions. Vue template/type/dependency build NOT performed.`);

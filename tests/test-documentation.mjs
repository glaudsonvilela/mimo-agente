import assert from 'node:assert/strict';
import {collectFindings,documentMarkdown} from '../frontend/src/documentation.js';
const security={tool:'qa_map',job_id:'a'.repeat(32),findings_total:101,findings_omitted:100,pages_total:101,pages_omitted:100,pages:[{url:'https://fixture.invalid/page',state:'failed',status:500,error:'HTTP 500'}],not_tested:'Controle de acesso não testado.',hypotheses:[{hypothesis:'Cookie sem Secure',url:'https://fixture.invalid/page',status:'confirmed_observation',severity:'medium',evidence:'HTTP 200; evidência 42; SHA256 abc',verification:'GET repetido',impact:'Impacto não confirmado.',recommendation:'Definir Secure.'}]};
const findings=collectFindings([security]);assert.equal(findings[0].severity,'medium');assert.equal(findings[0].recommendation,'Definir Secure.');assert.match(findings[0].evidence,/SHA256 abc/);assert.match(findings[0].confidence,/impacto não confirmado/);
const md=documentMarkdown({host:'fixture.invalid',scope:'https://fixture.invalid',updated:Date.now(),status:'Concluído',summary:'Teste',findings,security,sources:[],tools:['qa_map'],activities:[]});
assert.match(md,/omitidas nesta tela: 100/);assert.match(md,/HTTP 500/);assert.match(md,/Controle de acesso não testado/);assert.match(md,/Definir Secure/);
console.log('Documentation assertions passed: evidence, severity, correction, coverage, export limits.');

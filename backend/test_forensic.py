"""Phone acceptance tests for acquisition, custody, recovery and independent verification."""
import errno
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid
import zipfile

import qa_forensic as f
import qa_verify
import qa_crawler as qa
import qa_browser
from qa_lab import Lab, SESSION_A, SESSION_B
from qa_session import Session


class ForensicTests(unittest.TestCase):
    results=[]
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.keys=self.root/'keys';self.anchors=self.root/'anchors';self.path=self.root/uuid.uuid4().hex
        self.case=f.Case(self.path,self.keys,self.anchors,scope='http://127.0.0.1:8099/',minimum_free=0)
    def tearDown(self):self.temp.cleanup()
    @classmethod
    def tearDownClass(cls):
        output=f.ROOT/'qa-compat/forensic-tests.json';output.parent.mkdir(exist_ok=True)
        output.write_text(json.dumps(cls.results,ensure_ascii=False,indent=2));print('FORENSIC_RESULTS',output)
    def test_01_exact_original_encryption_and_permissions(self):
        payload=b'\x00RAW original\xff token=FICTIONAL_PRIVATE_VALUE'
        ident=self.case.put(payload,'http_body',{'request_id':1})
        item=next(a for a in self.case.artifacts() if a['id']==ident)
        self.assertEqual(self.case._read(item),payload)
        for path in self.path.rglob('*'):
            if path.is_file():self.assertNotIn(b'FICTIONAL_PRIVATE_VALUE',path.read_bytes())
        self.assertEqual((self.keys/'keys.json').stat().st_mode&0o777,0o600)
        self.assertEqual(self.path.stat().st_mode&0o777,0o700)
        self.assertEqual(self.case.verify()['artifacts'],1)

    def test_02_known_ed25519_vector_and_independent_openssl(self):
        # RFC 8032 section 7.1, TEST 1 (empty message).
        seed=bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
        signer=f.Ed25519PrivateKey.from_private_bytes(seed)
        signature=signer.sign(b'')
        self.assertEqual(signature.hex(),'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
        self.case.put(b'Known fixture','fixture')
        package=self.root/'case.zip';receipt=self.case.export(package)
        independent=qa_verify.verify_package(package,self.case.keys.fingerprint)
        self.assertTrue(independent['valid']);self.assertEqual(independent['manifest_sha256'],receipt['manifest_sha256'])
        self.results.append({'test':'independent_verifier','rfc8032_vector':True,'result':independent})

    def test_03_artifact_tampering_detected(self):
        ident=self.case.put(b'Important original','fixture');path=self.case.objects/(ident+'.enc')
        path.chmod(0o600);data=bytearray(path.read_bytes());data[-1]^=1;path.write_bytes(data)
        with self.assertRaises(Exception):self.case.verify()

    def test_04_tail_rollback_and_middle_deletion_detected(self):
        self.case.event('one');self.case.event('two')
        last=sorted(self.case.journal.glob('*.json'))[-1];saved=last.read_bytes();last.unlink()
        with self.assertRaises(f.IntegrityError):self.case.verify()
        f.atomic(last,saved,mode=0o400)
        (self.case.journal/'00000002.json').unlink()
        with self.assertRaises(f.IntegrityError):self.case.verify()

    def test_05_package_tamper_missing_member_and_traversal(self):
        self.case.put(b'Original','fixture');good=self.root/'good.zip';self.case.export(good)
        with zipfile.ZipFile(good) as source:contents={n:source.read(n) for n in source.namelist()}
        for mode in ('tamper','missing','traversal','duplicate'):
            dest=self.root/(mode+'.zip')
            with zipfile.ZipFile(dest,'w') as target:
                for name,data in contents.items():
                    if mode=='missing' and name.startswith('objects/'):continue
                    target.writestr(name,data+b'X' if mode=='tamper' and name.startswith('objects/') else data)
                if mode=='traversal':target.writestr('../escape',b'no')
                if mode=='duplicate':target.writestr('case.json',contents['case.json'])
            with self.assertRaises(Exception):qa_verify.verify_package(dest,self.case.keys.fingerprint)
        with self.assertRaises(ValueError):qa_verify.verify_package(good,'0'*64)

    def test_06_encrypted_key_backup_and_case_restore(self):
        ident=self.case.put(b'Recoverable evidence','fixture');original=(self.case.objects/(ident+'.enc')).read_bytes()
        archive=self.root/'backup.zip';self.case.export(archive,purpose='backup')
        password=b'FICTIONAL_RECOVERY_PASSWORD_34';backup=self.root/'keys.encrypted';self.case.keys.backup(backup,password)
        with self.assertRaises(Exception):f.Keys.restore(backup,self.root/'wrong',b'WRONG_PASSWORD_123456789')
        recovered=f.Keys.restore(backup,self.root/'new-keys',password)
        destination=self.root/'restored'/self.case.id
        result=f.restore_package(archive,destination,recovered.directory,self.root/'new-anchors',recovered.fingerprint)
        self.assertTrue(result['valid']);self.assertEqual((destination/'objects'/(ident+'.enc')).read_bytes(),original)
        restored=f.Case(destination,recovered.directory,self.root/'new-anchors')
        self.assertEqual(restored._read(restored.artifacts()[0]),b'Recoverable evidence')
        self.results.append({'test':'backup_restore','ciphertext_identical':True,'plaintext_identical':True,'wrong_password_rejected':True})

    def test_07_redaction_preserves_original_and_offline_html_is_inert(self):
        payload=b'<script>fetch("https://example.invalid/escaped")</script><input value="PERSONAL_NAME"><img src="https://example.invalid/image">'
        source=self.case.put(payload,'http_body');derived=self.case.derive_redaction(source,['PERSONAL_NAME'])
        self.assertEqual(self.case._read(next(a for a in self.case.artifacts() if a['id']==source)),payload)
        output=self.root/'review.html';self.case.review(output);document=output.read_text()
        self.assertNotIn('<script>',document);self.assertNotIn('<img ',document);self.assertNotIn('PERSONAL_NAME',document)
        self.assertIn('&lt;script&gt;',document);self.assertIn('default-src',document)
        if qa_browser.available():
            requests=[]
            def transport(url,method,kind,**kwargs):
                requests.append(url)
                if url!='http://127.0.0.1:8099/review':raise ValueError('Unexpected network request')
                return {'status':200,'headers':{'content-type':'text/html'},'body':output.read_bytes()}
            rendered=qa_browser.render('http://127.0.0.1:8099/review',transport,threading.Event(),time.monotonic()+10)
            self.assertTrue(rendered['javascript_executed']);self.assertEqual(requests,['http://127.0.0.1:8099/review'])
            self.results.append({'test':'offline_review_browser','external_requests':0,'scripts_and_images_escaped':True})

    def test_08_imported_logs_and_clock_uncertainty(self):
        log=self.root/'server.jsonl';log.write_text('{"timestamp":"2026-11-06T12:00:00Z","path":"/example","status":200}\n{"timestamp":"2026-11-06T12:00:01","path":"/ambiguous"}\nnot json\n')
        self.case.import_log(log,'operator supplied lab server')
        timeline=self.case.timeline();times=[r for r in timeline if 'time_assurance' in r]
        self.assertEqual([r['time_assurance'] for r in times],['operator_log_unverified','missing_or_ambiguous_timezone','unparsed'])
        now=f.clock_record();now['wall_ns']+=10_000_000_000
        self.assertEqual(f.clock_record(now)['warning'],'wall_clock_jump')
        now['boot_id']='other-boot';self.assertIn('boot_changed',f.clock_record(now)['warning'])

    def test_09_claims_require_evidence_and_model_provenance(self):
        artifact=self.case.put(b'Fact source','fixture')
        valid={'analysis_type':'model','model':'fixture-model','model_version':'sha256:fixture','configuration':{'temperature':0},'conclusions':[{'classification':'hypothesis','statement':'Fictional hypothesis','evidence_ids':[artifact]}]}
        self.case.add_analysis(valid)
        bad=json.loads(json.dumps(valid));bad['conclusions'][0]['evidence_ids']=[]
        with self.assertRaises(ValueError):self.case.add_analysis(bad)
        bad=json.loads(json.dumps(valid));bad['model_version']=None
        with self.assertRaises(ValueError):self.case.add_analysis(bad)
        bad=json.loads(json.dumps(valid));bad['conclusions'][0]['evidence_ids']=['nonexistent']
        with self.assertRaises(ValueError):self.case.add_analysis(bad)
        bad=json.loads(json.dumps(valid));bad['configuration']['api_key']='FICTIONAL_SECRET'
        with self.assertRaises(ValueError):self.case.add_analysis(bad)

    def test_10_storage_quota_and_enospc_preserve_committed_evidence(self):
        self.case.put(b'Existing committed evidence','fixture');before=self.case.verify(record=False)
        self.case.max_bytes=1024
        with self.assertRaises(f.StorageLimit):self.case.put(b'Next','fixture')
        self.case.max_bytes=128*1024*1024
        with patch('qa_forensic.os.fsync',side_effect=OSError(errno.ENOSPC,'fixture disk full')):
            with self.assertRaises(OSError):self.case.put(b'Interrupted write','fixture')
        after=self.case.verify(record=False);self.assertEqual(before['head'],after['head'])
        with patch('qa_forensic.shutil.disk_usage',return_value=shutil._ntuple_diskusage(100,100,0)):
            with self.assertRaises(f.StorageLimit):self.case.put(b'No space','fixture')
        self.assertEqual(before['head'],self.case.verify(record=False)['head'])
        self.results.append({'test':'storage_failure','quota_pause':True,'enospc_injected':True,'committed_evidence_preserved':True,'device_disk_not_filled':True})

    def test_11_sigkill_between_object_and_journal_recovers_original(self):
        child='''import sys,os,signal
from pathlib import Path
import qa_forensic as f
c=f.Case(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
old=c._append
def crash(action,detail,events):
 if action=="artifact_acquired":os.kill(os.getpid(),signal.SIGKILL)
 return old(action,detail,events)
c._append=crash
c.put(b"Evidence survives power-like interruption","fixture")
'''
        result=subprocess.run([sys.executable,'-c',child,str(self.path),str(self.keys),str(self.anchors)],cwd=f.ROOT,capture_output=True)
        self.assertEqual(result.returncode,-signal.SIGKILL,result.stderr)
        recovered=f.Case(self.path,self.keys,self.anchors);items=recovered.artifacts()
        self.assertEqual(items[0]['kind'],'recovered_uncommitted');self.assertEqual(recovered._read(items[0]),b'Evidence survives power-like interruption')
        self.assertTrue(recovered.verify()['valid'])
        self.results.append({'test':'sigkill_atomic_recovery','original_preserved':True,'lost_association_explicit':True})

    def test_12_encrypted_browser_acquisition_and_session(self):
        lab=Lab(tls=True);ca=str(f.ROOT/'qa-fixtures/lab-cert.pem')
        try:
            forensic={'enabled':True,'key_dir':str(self.keys),'anchors':str(self.anchors),'backup_dir':str(self.root/'backups'),'minimum_free':0}
            crawler=qa.Crawler(self.root/'map.sqlite',scope=lab.origin+'/rotate',lab=True,javascript=True,tls_ca=ca,
                session=Session(lab.scope,{'Cookie':'session='+SESSION_A},lab=True),forensic=forensic,options={'requests':40,'pages':20,'depth':2,'seconds':90,'interval':.25})
            begin=time.monotonic()
            try:report=crawler.run();case=crawler.case
            finally:crawler.close()
            self.assertEqual(report['forensic']['status'],'preserved',report.get('forensic'))
            items=case.artifacts();self.assertTrue(any(a['kind']=='rendered_dom' for a in items))
            self.assertTrue(any(a['kind']=='http_response_headers' for a in items))
            for path in case.path.rglob('*'):
                if path.is_file():
                    raw=path.read_bytes();self.assertNotIn(SESSION_A.encode(),raw);self.assertNotIn(SESSION_B.encode(),raw)
            for item in items:
                if item['kind']=='redacted_preview':self.assertNotIn(SESSION_B.encode(),case._read(item))
            verified=qa_verify.verify_package(report['forensic']['backup'],case.keys.fingerprint)
            self.assertTrue(verified['valid']);self.assertFalse(lab.outside_hits);self.assertFalse(lab.posts)
            self.results.append({'test':'phone_browser_acquisition','seconds':round(time.monotonic()-begin,3),'requests':report['requests'],
                                 'artifacts':len(items),'encrypted_package_bytes':Path(report['forensic']['backup']).stat().st_size,'independent_verification':verified})
        finally:lab.close()

    def test_13_crawler_storage_failure_is_not_success(self):
        lab=Lab()
        try:
            crawler=qa.Crawler(self.root/'limited.sqlite',scope=lab.scope,lab=True,javascript=False,
                forensic={'enabled':True,'key_dir':str(self.keys),'anchors':str(self.anchors),'backup_dir':str(self.root/'backups'),'minimum_free':0})
            crawler.case.max_bytes=1024
            try:report=crawler.run()
            finally:crawler.close()
            self.assertEqual(report['status'],'paused');self.assertEqual(report['forensic']['status'],'incomplete')
            self.assertGreater(report['coverage']['pending'],0)
        finally:lab.close()

    def test_14_metadata_and_symlink_tampering_fail_closed(self):
        self.case.put(b'Original','fixture')
        meta=json.loads(self.case.meta.read_text());meta['encryption']='none';self.case.meta.write_text(json.dumps(meta))
        with self.assertRaises(f.IntegrityError):self.case.verify()
        target=self.root/'symlink'
        try:target.symlink_to(self.keys/'keys.json')
        except (PermissionError,NotImplementedError):self.assertFalse(target.exists())
        else:
            with self.assertRaises(OSError):f.read_regular(target)

    def test_15_missing_anchor_and_concurrent_writers(self):
        child='''import sys
from pathlib import Path
import qa_forensic as f
c=f.Case(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
for n in range(5):c.put((sys.argv[4]+str(n)).encode(),"concurrent_fixture")
'''
        processes=[subprocess.Popen([sys.executable,'-c',child,str(self.path),str(self.keys),str(self.anchors),str(n)],cwd=f.ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for n in range(2)]
        for process in processes:
            out,err=process.communicate(timeout=30);self.assertEqual(process.returncode,0,err)
        self.assertEqual(self.case.verify(record=False)['artifacts'],10)
        self.case.anchor.unlink()
        with self.assertRaises(f.IntegrityError):self.case.verify()


if __name__=='__main__':unittest.main(verbosity=2)

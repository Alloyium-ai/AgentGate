# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Focused host, failure, identity, and image contract checks."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import appliance as cli
import appliance_common as common
from image_contract import validate_image


class ApplianceTest(unittest.TestCase):
    def directory(self):
        value = tempfile.TemporaryDirectory()
        self.addCleanup(value.cleanup)
        return Path(value.name)

    def test_unsupported_host_stops_before_docker(self):
        with patch('appliance_common.platform.system', return_value='Darwin'), patch('appliance_common.run') as run:
            with self.assertRaisesRegex(ValueError, 'supported host'):
                common.preflight()
            run.assert_not_called()

    def test_protected_state_rejects_symlink_and_open_mode(self):
        root = self.directory()
        file = root/'secret'; file.write_text('secret'); file.chmod(0o600)
        self.assertEqual(common.protected(file), b'secret')
        (root/'link').symlink_to(file)
        with self.assertRaises(OSError):common.protected(root/'link')
        file.chmod(0o644)
        with self.assertRaises(ValueError):common.protected(file)
        (root/'dir-link').symlink_to(root, target_is_directory=True)
        with self.assertRaises(ValueError):cli.state_directory(str(root/'dir-link'/'new'))

    def test_scp_preserves_pinned_host_and_management_identity(self):
        root=self.directory();binding={'name':'test', 'port':22365}
        with patch('appliance_common.run') as run:
            common.copy_guest(root,binding,root/'input','/root/input')
        args=run.call_args.args[0]
        self.assertEqual(args[0],'scp');self.assertIn('-P',args);self.assertNotIn('-p',args)
        self.assertIn('StrictHostKeyChecking=yes',args)
        self.assertIn(str(root/'management-key'),args)
        self.assertNotIn(str(root/'workload-key'),args)

    def test_matching_rejects_source_base_port_and_policy_changes(self):
        root=self.directory();common.write(root/'policy.json',b'{}')
        common.write(root/'taskboard.token',b'token')
        import hashlib
        binding={'revision':'a'*40,'coding_base':'ubuntu@sha256:test','port':22365,
                 'policy_sha256':hashlib.sha256(b'{}').hexdigest()}
        args=argparse.Namespace(revision='a'*40,coding_base=None,port=None,policy=None,token_file=None)
        with patch('appliance.revision',return_value='a'*40):
            cli.matching(root,args,binding)
            args.port=22366
            with self.assertRaises(ValueError):cli.matching(root,args,binding)
            args.port=None;args.coding_base='different'
            with self.assertRaises(ValueError):cli.matching(root,args,binding)
        with patch('appliance.revision',return_value='b'*40):
            with self.assertRaises(ValueError):cli.matching(root,args,binding)

    def test_existing_key_is_verified_and_reused(self):
        root=self.directory();common.write(root/'key',b'private');(root/'key.pub').write_text('ssh-ed25519 public comment')
        with patch('appliance.output',return_value='ssh-ed25519 public'),patch('appliance.run') as run:
            cli.key(root,'key');run.assert_not_called()
        with patch('appliance.output',return_value='ssh-ed25519 changed'):
            with self.assertRaises(ValueError):cli.key(root,'key')

    def test_image_volume_contract_fails_before_execution(self):
        raw=json.dumps([{'Config':{'Volumes':{'/data':{}}}}]).encode()
        with patch('image_contract.subprocess.check_output',return_value=raw),patch('image_contract.subprocess.run') as run:
            with self.assertRaisesRegex(ValueError,'volumes'):validate_image('image')
            run.assert_not_called()

    def test_cloud_init_contains_real_newlines_and_pinned_keys(self):
        root=self.directory();(root/'binding.json').write_text(json.dumps({'name':'test'}))
        for name,content in [('management-key.pub','ssh-ed25519 management'),('guest-host-key','PRIVATE\nKEY\n'),('guest-host-key.pub','ssh-ed25519 host')]:
            (root/name).write_text(content)
        path=Path(__file__).parent/'appliance/boot.py'
        spec=importlib.util.spec_from_file_location('appliance_boot',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with patch.object(module,'ROOT',root),patch.object(module,'run'):
            module.seed()
        text=(root/'user-data').read_text();self.assertTrue(text.startswith('#cloud-config\n{'))
        data=json.loads(text.split('\n',1)[1]);self.assertEqual(data['ssh_keys']['ed25519_private'],'PRIVATE\nKEY\n')
        self.assertEqual(data['users'][0]['ssh_authorized_keys'],['ssh-ed25519 management'])
        self.assertIn('docker.io',data['packages'])

    def test_guest_archive_root_custody_preserves_private_mode(self):
        import tarfile
        from appliance_guest import guest_owner
        info=tarfile.TarInfo('taskboard.token');info.uid=info.gid=1000;info.mode=0o600
        result=guest_owner(info)
        self.assertEqual((result.uid,result.gid,result.mode),(0,0,0o600))

    def test_idle_transition_accepts_case_variants_and_refuses_other_errors(self):
        import shlex
        from types import SimpleNamespace
        from appliance_guest import transition
        with patch('appliance_guest.admin') as admin:
            transition(Path('/state'), {}, True)
        code=shlex.split(admin.call_args.args[2])[-1]
        for status,error,allowed in [(1,b'error: no such object: target',True),
                                     (1,b'No such object: target',True),
                                     (1,b'Cannot connect to Docker',False),(0,b'',False)]:
            with patch('pathlib.Path') as path,patch('subprocess.run',return_value=SimpleNamespace(returncode=status,stderr=error)):
                path.return_value.exists.return_value=False
                if allowed:exec(code,{})
                else:
                    with self.assertRaisesRegex(AssertionError,'owned target remains'):exec(code,{})

    def test_interrupted_write_does_not_block_later_writes(self):
        root=self.directory();(root/'binding.json.new').write_bytes(b'partial')
        common.write(root/'binding.json',b'{}')
        self.assertEqual((root/'binding.json').read_bytes(),b'{}')
        self.assertFalse((root/'binding.json.new').exists())
        self.assertEqual((root/'binding.json').stat().st_mode & 0o777,0o600)

    def test_missing_instance_explains_how_to_start(self):
        with self.assertRaisesRegex(ValueError,'run start --policy FILE --token-file FILE'):
            common.load(self.directory())

    def test_concurrent_command_gets_a_clear_busy_message(self):
        import fcntl
        root=self.directory();root.chmod(0o700)
        fd=os.open(root/'control.lock',os.O_RDWR|os.O_CREAT,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
            with patch('sys.argv',['appliance.py','status','--state',str(root)]),patch('appliance.preflight'):
                with self.assertRaisesRegex(RuntimeError,'another appliance command'):
                    cli.main()
        finally:
            os.close(fd)

    def test_export_requires_named_tag_and_hashes_config_bytes(self):
        import hashlib,tarfile,io
        from appliance_build import archive_digests
        root=self.directory();path=root/'images.tar';raw=b'{"architecture":"amd64"}'
        rows=[{'Config':'config.json','RepoTags':['owned-'+name+':latest']} for name in ('target','bridge')]
        with tarfile.open(path,'w') as archive:
            for name,data in [('manifest.json',json.dumps(rows).encode()),('config.json',raw)]:
                info=tarfile.TarInfo(name);info.size=len(data);archive.addfile(info,io.BytesIO(data))
        expected='sha256:'+hashlib.sha256(raw).hexdigest()
        self.assertEqual(archive_digests(path,'owned'),{'target':expected,'bridge':expected})
        with self.assertRaises(ValueError):archive_digests(path,'different')

    def test_oci_manifest_is_bound_to_exact_config_and_diff_ids(self):
        import hashlib,tarfile,io
        from appliance_build import archive_identity
        root=self.directory();path=root/'images.tar'
        config=json.dumps({'rootfs':{'type':'layers','diff_ids':['sha256:layer']}}).encode()
        cfg='sha256:'+hashlib.sha256(config).hexdigest()
        manifest=json.dumps({'schemaVersion':2,'config':{'digest':cfg},'layers':[{'digest':'sha256:compressed'}]}).encode()
        digest='sha256:'+hashlib.sha256(manifest).hexdigest()
        entries=[{'Config':'config.json','RepoTags':['owned-'+name+':latest']} for name in ('target','bridge')]
        with tarfile.open(path,'w') as archive:
            for name,data in [('manifest.json',json.dumps(entries).encode()),('config.json',config),('blobs/sha256/'+digest[7:],manifest)]:
                info=tarfile.TarInfo(name);info.size=len(data);archive.addfile(info,io.BytesIO(data))
        for item in archive_identity(path,'owned').values():
            self.assertEqual(item['config_digest'],cfg)
            self.assertEqual(item['manifest_digests'],[digest])
            self.assertEqual(item['rootfs_diff_ids'],['sha256:layer'])

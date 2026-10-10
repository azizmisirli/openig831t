# SPDX-License-Identifier: Apache-2.0
"""Publisher gates on synthetic data and local temp files; no network or devices."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import publish_github as p
from scripts.build_bundle import build

A, B, TREE = 'a'*40, 'b'*40, 'c'*40


def completed(stdout='', code=0, stderr=''):
    return subprocess.CompletedProcess([], code, stdout, stderr)


def synthetic_run(name='CI', number=1, **changes):
    value = dict(name=name, id=number, run_attempt=1, head_sha=A, head_branch='main',
                 event='push', path=p.WORKFLOWS[name], status='completed', conclusion='success', html_url='https://example.invalid/run')
    value.update(changes)
    return value


class PublisherTests(unittest.TestCase):
    def setUp(self):
        # Tests which intentionally exercise command/HTTP wrappers override these
        # guards with injected fakes; accidental real subprocess or HTTP use fails.
        self.process_guard = patch.object(subprocess, 'run', side_effect=AssertionError('No real subprocess allowed'))
        self.http_guard = patch.object(p.urllib.request, 'build_opener', side_effect=AssertionError('No real HTTP allowed'))
        self.process_guard.start(); self.http_guard.start()
        self.addCleanup(self.process_guard.stop); self.addCleanup(self.http_guard.stop)

    def test_default_plan_does_not_call_publish_or_network(self):
        with patch.object(p.sys, 'argv', ['publish_github.py']), patch.object(p, 'publish') as publish:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(p.main(), 0)
            publish.assert_not_called()

    def test_atomic_checkpoint_replaces_complete_document(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(p, 'ROOT', Path(tmp)):
            (Path(tmp)/'.git').mkdir()
            p.write_state({'format_version': 2, 'release_commit': A})
            p.write_state({'format_version': 2, 'release_commit': B})
            path = Path(tmp)/'.git/openig831t-publication.json'
            self.assertEqual(json.loads(path.read_text())['release_commit'], B)
            self.assertFalse(path.with_suffix('.tmp').exists())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_local_gates_precede_missing_auth_stop(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(p, 'ROOT', Path(tmp)):
            (Path(tmp)/'.git').mkdir(); order = []
            with patch.object(p, 'setup_python', return_value=('python', {})), \
                 patch.object(p, 'checks', side_effect=lambda *a: order.append('local')), \
                 patch.object(p, 'run', side_effect=lambda *a, **kw: (order.append('auth') or completed(code=1))), \
                 patch.object(p, 'gh_json') as gh:
                with self.assertRaisesRegex(RuntimeError, 'AUTH_REQUIRED'):
                    p.publish()
                self.assertEqual(order, ['local', 'auth']); gh.assert_not_called()

    def test_only_http_404_is_absence(self):
        for message in ('HTTP 403', 'HTTP 401', 'connection failed', '404 bytes unavailable'):
            with self.subTest(message=message), patch.object(p, 'run', return_value=completed(code=1, stderr=message)):
                with self.assertRaises(RuntimeError):
                    p.api_optional('synthetic/path')
        with patch.object(p, 'run', return_value=completed(code=1, stderr='gh: Not Found (HTTP 404)')):
            self.assertIsNone(p.api_optional('synthetic/path'))

    def test_newest_run_cannot_be_hidden_by_old_success(self):
        data = {'workflow_runs': [synthetic_run(number=1), synthetic_run(number=2, conclusion='failure')]}
        self.assertEqual(p.latest_runs(data, A)['CI']['conclusion'], 'failure')
        with patch.object(p, 'expected_job_names', return_value={n: set() for n in p.WORKFLOWS}), \
             patch.object(p, 'gh_json', return_value={'workflow_runs': data['workflow_runs']+
                        [synthetic_run(n) for n in p.WORKFLOWS if n != 'CI']}):
            with self.assertRaisesRegex(RuntimeError, 'Newest exact-commit CI failed'):
                p.wait_ci('owner/repo', A, timeout=1)

    def test_wrong_sha_event_branch_and_path_do_not_count(self):
        variants = [dict(head_sha=B), dict(event='pull_request'), dict(head_branch='feature'),
                    dict(path='.github/workflows/unrelated.yml')]
        for change in variants:
            self.assertEqual(p.latest_runs({'workflow_runs': [synthetic_run(**change)]}, A), {})
        self.assertEqual(p.latest_runs({'workflow_runs': [synthetic_run(run_attempt=2), synthetic_run()]}, A)['CI']['run_attempt'], 2)

    def test_actual_workflow_job_names_are_derived(self):
        self.assertEqual(p.expected_job_names(), {
            'CI': {'Offline tests (3.10)', 'Offline tests (3.12)', 'Offline tests (3.14)'},
            'Documentation': {'Documentation and evidence'}, 'Security scan': {'Publication audit'}})

    def test_missing_skipped_extra_or_truncated_jobs_fail(self):
        runs = {'workflow_runs': [synthetic_run(n) for n in p.WORKFLOWS]}
        expected = {n: {'actual job'} for n in p.WORKFLOWS}
        fixtures = [dict(total_count=1, jobs=[]), dict(total_count=1, jobs=[dict(name='actual job', conclusion='skipped')]),
                    dict(total_count=1, jobs=[dict(name='wrong name', conclusion='success')]),
                    dict(total_count=2, jobs=[dict(name='actual job', conclusion='success')])]
        for jobs in fixtures:
            with self.subTest(jobs=jobs), patch.object(p, 'expected_job_names', return_value=expected), \
                 patch.object(p, 'gh_json', side_effect=lambda *args: runs if 'actions/runs?' in args[-1] else jobs):
                with self.assertRaisesRegex(RuntimeError, 'CI jobs'):
                    p.wait_ci('owner/repo', A, timeout=1)

    def test_successful_ci_records_real_names_and_run_attempt(self):
        runs = {'workflow_runs': [synthetic_run(n, run_attempt=2) for n in p.WORKFLOWS]}
        with patch.object(p, 'expected_job_names', return_value={n: {'actual job'} for n in p.WORKFLOWS}), \
             patch.object(p, 'gh_json', side_effect=lambda *args: runs if 'actions/runs?' in args[-1] else
                          dict(total_count=1, jobs=[dict(name='actual job', conclusion='success')])) as gh:
            value = p.wait_ci('owner/repo', A, timeout=1)
            self.assertEqual(value['CI']['jobs'], ['actual job']); self.assertEqual(value['CI']['attempt'], 2)
            self.assertTrue(any('/attempts/2/jobs' in c.args[-1] for c in gh.call_args_list))

    def test_annotation_is_peeled_and_mismatching_tag_is_refused(self):
        with patch.object(p, 'gh_json', side_effect=[{'object': {'type': 'tag', 'sha': B}},
                                                   {'object': {'type': 'commit', 'sha': A}}]):
            p.verify_tag('owner/repo', A)
        with patch.object(p, 'gh_json', return_value={'object': {'type': 'commit', 'sha': B}}):
            with self.assertRaisesRegex(RuntimeError, 'never overwritten'):
                p.verify_tag('owner/repo', A)
        with patch.object(p, 'gh_json', return_value={'object': {'type': 'tag', 'sha': B}}) as gh:
            with self.assertRaises(RuntimeError):
                p.verify_tag('owner/repo', A)
            self.assertEqual(gh.call_count, 9)

    def test_commit_after_crash_recovers_without_another_commit(self):
        state = {'pending_commit': {'key': 'final_commit', 'parent': A, 'tree': TREE, 'message': 'synthetic'}}
        with patch.object(p, 'head', return_value=B), patch.object(p, 'run', side_effect=[completed(A), completed(TREE)]) as run, \
             patch.object(p, 'write_state'):
            p.recover_commit(state)
            self.assertEqual(state, {'final_commit': B})
            self.assertFalse(any('commit' in call.args[0] for call in run.call_args_list))

    def test_commit_identity_ignores_personal_environment_overrides(self):
        state = {'pending_commit': {'key': 'release_commit', 'parent': A, 'tree': TREE, 'message': 'synthetic'}}
        with patch.dict(p.os.environ, {'GIT_AUTHOR_NAME': 'Synthetic Personal Name',
                                      'GIT_COMMITTER_NAME': 'Synthetic Personal Name',
                                      'GIT_AUTHOR_EMAIL': 'synthetic'+'@'+'example.invalid',
                                      'GIT_COMMITTER_EMAIL': 'synthetic'+'@'+'example.invalid',
                                      'EMAIL': 'synthetic'+'@'+'example.invalid'}), \
             patch.object(p, 'head', side_effect=[A, B]), \
             patch.object(p, 'run', side_effect=[completed(TREE), completed(), completed(A), completed(TREE)]) as run, \
             patch.object(p, 'write_state'):
            p.recover_commit(state)
        commit_call = next(call for call in run.call_args_list if call.args[0][:2] == ['git', 'commit'])
        env = commit_call.kwargs['env']
        self.assertEqual(env['GIT_AUTHOR_NAME'], 'OpenIG831T contributors')
        self.assertEqual(env['GIT_COMMITTER_NAME'], 'OpenIG831T contributors')
        for key in ('GIT_AUTHOR_EMAIL', 'GIT_COMMITTER_EMAIL', 'EMAIL'):
            self.assertEqual(env[key], '')

    def test_citation_uses_collective_without_author_email_or_profile(self):
        url = 'https://github.com/synthetic-owner/openig831t'
        metadata = p.citation_metadata(url, '2026-10-10')
        self.assertEqual(metadata['authors'], [{'name': 'OpenIG831T contributors'}])
        self.assertEqual(metadata['repository-code'], url)
        self.assertEqual(metadata['url'], url)
        self.assertNotIn('website', metadata['authors'][0])
        self.assertNotIn('email', metadata['authors'][0])

    def test_precommit_crash_reuses_staged_tree(self):
        state = {'pending_commit': {'key': 'release_commit', 'parent': A, 'tree': TREE, 'message': 'synthetic'}}
        with patch.object(p, 'head', side_effect=[A, B]), \
             patch.object(p, 'run', side_effect=[completed(TREE), completed(), completed(A), completed(TREE)]) as run, \
             patch.object(p, 'write_state'):
            p.recover_commit(state)
            self.assertEqual(state['release_commit'], B)
            self.assertEqual(sum(call.args[0][:2] == ['git', 'commit'] for call in run.call_args_list), 1)

    def test_recovery_rejects_changed_index_or_unrelated_commit(self):
        pending = {'key': 'final_commit', 'parent': A, 'tree': TREE, 'message': 'synthetic'}
        for current, responses in [(A, [completed(B)]), (B, [completed(TREE), completed(TREE)]),
                                   (B, [completed(A), completed(A)])]:
            with patch.object(p, 'head', return_value=current), patch.object(p, 'run', side_effect=responses), \
                 patch.object(p, 'write_state') as write:
                with self.assertRaises(RuntimeError):
                    p.recover_commit({'pending_commit': pending})
                write.assert_not_called()

    def test_interrupted_metadata_only_permits_declared_paths(self):
        for result in (' M other.py\0', 'R  PUBLICATION_RESULT.md\0prior.md\0'):
            with patch.object(p, 'head', return_value=A), patch.object(p, 'run', return_value=completed(result)):
                with self.assertRaises(RuntimeError):
                    p.permit_generated_changes({'PUBLICATION_RESULT.md'}, A)
        with patch.object(p, 'head', return_value=A), patch.object(p, 'run', return_value=completed(' M PUBLICATION_RESULT.md\0')):
            p.permit_generated_changes({'PUBLICATION_RESULT.md'}, A)

    def bundle_fixture(self, root):
        source = root/'source'; source.mkdir()
        (source/'README.md').write_text('# Synthetic only\n')
        (source/'code.py').write_text('pass\n')
        output = root/'bundle'; build(source, output)
        objects = {f.name: hashlib.sha1(b'blob '+str(len(f.read_bytes())).encode()+b'\0'+f.read_bytes()).hexdigest()
                   for f in source.iterdir()}
        return output, objects

    def test_bundle_checks_all_four_assets_and_git_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, objects = self.bundle_fixture(Path(tmp))
            self.assertEqual(set(p.verify_bundle(out, objects)), p.ASSETS)
            with self.assertRaisesRegex(RuntimeError, 'Git tree|release commit'):
                p.verify_bundle(out, dict(objects, **{'code.py': A}))
            with self.assertRaisesRegex(RuntimeError, 'tracked release file set'):
                p.verify_bundle(out, {'README.md': objects['README.md']})

    def test_bundle_extra_missing_corrupt_or_symlink_asset_fails(self):
        for mode in ('extra', 'missing', 'corrupt', 'symlink'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); out, objects = self.bundle_fixture(root)
                if mode == 'extra':
                    (out/'unexpected.txt').write_text('synthetic')
                elif mode == 'missing':
                    (out/'manifest.json').unlink()
                elif mode == 'corrupt':
                    (out/'manifest.json').write_text('{}')
                else:
                    (out/'manifest.json').rename(root/'manifest.json')
                    (out/'manifest.json').symlink_to(root/'manifest.json')
                with self.assertRaises(RuntimeError):
                    p.verify_bundle(out, objects)

    def test_archive_duplicate_traversal_link_and_unknown_member_rejected(self):
        for mode in ('duplicate', 'traversal', 'link', 'unknown'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                archive = Path(tmp)/'synthetic.tar.gz'
                with tarfile.open(archive, 'w:gz') as tar:
                    info = tarfile.TarInfo('openig831t/ok.txt'); info.size = 1
                    tar.addfile(info, io.BytesIO(b'x'))
                    name = 'openig831t/ok.txt' if mode == 'duplicate' else 'openig831t/../escape' if mode == 'traversal' else 'openig831t/other'
                    extra = tarfile.TarInfo(name); extra.size = 1
                    if mode == 'link':
                        extra.type = tarfile.SYMTYPE; extra.linkname = 'ok.txt'; extra.size = 0
                    tar.addfile(extra, io.BytesIO(b'x'))
                with self.assertRaises(RuntimeError):
                    p.inspect_archive(archive, {'ok.txt': p.digest(b'x')})

    def test_anonymous_download_requires_exact_bytes_not_just_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp); (out/'manifest.json').write_bytes(b'good')
            row = {'name': 'manifest.json', 'state': 'uploaded', 'size': 4,
                   'browser_download_url': f'https://github.com/owner/repo/releases/download/{p.TAG}/manifest.json'}
            release = dict(tag_name=p.TAG, draft=False, prerelease=True, assets=[row])
            with patch.object(p, 'anonymous_bytes', return_value=b'evil'):
                with self.assertRaisesRegex(RuntimeError, 'checksum'):
                    p.verify_remote_assets('owner/repo', release, {'manifest.json': p.digest(b'good')}, out, True)
            with patch.object(p, 'anonymous_bytes', return_value=b'good'):
                p.verify_remote_assets('owner/repo', release, {'manifest.json': p.digest(b'good')}, out, True)
            release['assets'].append(copy.deepcopy(row))
            with self.assertRaisesRegex(RuntimeError, 'assets differ'):
                p.verify_remote_assets('owner/repo', release, {'manifest.json': p.digest(b'good')}, out, True)

    def test_empty_partial_release_does_not_download_or_overwrite(self):
        release = dict(tag_name=p.TAG, draft=False, prerelease=True, assets=[])
        with patch.object(p, 'run') as run:
            p.verify_remote_assets('owner/repo', release, {}, Path('/unused'))
            run.assert_not_called()

    def test_unsupported_optional_setting_is_reported_not_enabled(self):
        with patch.object(p, 'run', return_value=completed(code=1, stderr='HTTP 403')):
            self.assertEqual(p.optional_setting(['synthetic']), 'UNAVAILABLE_OR_PERMISSION_DENIED')
        with patch.object(p, 'run', return_value=completed(code=1, stderr='TLS error')):
            with self.assertRaises(RuntimeError):
                p.optional_setting(['synthetic'])

    def test_anonymous_environment_strips_credentials_and_proxies(self):
        with patch.dict(p.os.environ, {'GH_TOKEN': 'synthetic', 'GITHUB_TOKEN': 'synthetic',
                                       'HTTPS_PROXY': 'synthetic', 'GIT_CONFIG_COUNT': '1', 'GIT_ASKPASS': 'synthetic',
                                       'HOME': '/synthetic-original-home', 'XDG_CONFIG_HOME': '/synthetic-original-config'}, clear=True):
            env = p.anonymous_git_env(Path('/synthetic-isolated-home'))
        self.assertEqual(env, {'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_GLOBAL': p.os.devnull, 'GIT_CONFIG_NOSYSTEM': '1',
                               'HOME': '/synthetic-isolated-home', 'CURL_HOME': '/synthetic-isolated-home',
                               'XDG_CONFIG_HOME': '/synthetic-isolated-home/config'})

    def test_asset_verification_failure_prevents_visibility(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(p, 'ROOT', Path(tmp)):
            root = Path(tmp); (root/'.git').mkdir(); (root/'dist'/('release-'+A)).mkdir(parents=True)
            state = {'format_version': 2, 'owner': 'synthetic-owner', 'repository': 'synthetic-owner/openig831t',
                     'repository_id': 99, 'release_commit': A}
            (root/'.git/openig831t-publication.json').write_text(json.dumps(state))
            repo = state['repository']; release = dict(tag_name=p.TAG, draft=False, prerelease=True,
                assets=[dict(name=name) for name in p.ASSETS])
            command = Mock(side_effect=lambda args, **kw: completed(
                'https://github.com/'+repo+'.git' if args[:3] == ['git', 'remote', 'get-url'] else ''))
            replacements = {'setup_python': Mock(return_value=('python', {})), 'checks': Mock(),
                'require_clean': Mock(), 'repository': Mock(return_value={'private': True}), 'run': command,
                'gh_json': Mock(return_value={'login': 'synthetic-owner', 'id': 123}),
                'api_optional': Mock(return_value=release), 'wait_ci': Mock(return_value={}),
                'assert_remote_head': Mock(), 'verify_clone': Mock(), 'tree_objects': Mock(return_value={}),
                'verify_bundle': Mock(return_value={name: 'synthetic' for name in p.ASSETS}),
                'verify_tag': Mock(), 'verify_remote_assets': Mock(side_effect=RuntimeError('synthetic mismatch')),
                'write_state': Mock()}
            with contextlib.ExitStack() as stack:
                for name, value in replacements.items():
                    stack.enter_context(patch.object(p, name, value))
                with self.assertRaisesRegex(RuntimeError, 'synthetic mismatch'):
                    p.publish()
            self.assertFalse(any('--visibility' in c.args[0] for c in command.call_args_list))

    def test_existing_completed_checkpoint_does_not_move_tag_or_recommit(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(p, 'ROOT', Path(tmp)):
            root = Path(tmp); (root/'.git').mkdir(); (root/'dist'/('release-'+A)).mkdir(parents=True)
            state = {'format_version': 2, 'owner': 'synthetic-owner', 'repository': 'synthetic-owner/openig831t',
                     'repository_id': 99, 'release_commit': A, 'final_commit': B,
                     'visibility_intent': True, 'asset_hashes': {'synthetic': 'hash'}, 'completed': True,
                     'release_private_verified_commit': A}
            (root/'.git/openig831t-publication.json').write_text(json.dumps(state))
            repo = state['repository']; current = {'id': 99, 'private': False, 'default_branch': 'main'}
            release = {'tag_name': p.TAG, 'draft': False, 'prerelease': True,
                       'assets': [dict(name=name) for name in p.ASSETS]}
            def api(*args):
                if args[-1] == 'user':
                    return {'login': 'synthetic-owner', 'id': 123}
                return current
            def anonymous(url):
                return release if '/releases/tags/' in url else current
            def command(args, **kwargs):
                return completed('https://github.com/'+repo+'.git' if args[:3] == ['git', 'remote', 'get-url'] else '')
            patches = {'setup_python': Mock(return_value=('python', {})), 'checks': Mock(),
                       'require_clean': Mock(), 'repository': Mock(return_value=current), 'run': Mock(side_effect=command),
                       'gh_json': Mock(side_effect=api), 'api_optional': Mock(return_value=release),
                       'wait_ci': Mock(return_value={'CI': {'jobs': ['actual job']}}), 'assert_remote_head': Mock(),
                       'verify_clone': Mock(), 'tree_objects': Mock(return_value={}),
                       'verify_bundle': Mock(return_value=state['asset_hashes']), 'verify_tag': Mock(),
                       'verify_remote_assets': Mock(), 'anonymous_json': Mock(side_effect=anonymous),
                       'settings': Mock(return_value={}), 'write_state': Mock(), 'write_report': Mock(),
                       'checkpoint_commit': Mock()}
            with contextlib.ExitStack() as stack, contextlib.redirect_stdout(io.StringIO()):
                for name, value in patches.items():
                    stack.enter_context(patch.object(p, name, value))
                p.publish()
            patches['checkpoint_commit'].assert_not_called(); patches['write_report'].assert_not_called()
            commands = [call.args[0] for call in patches['run'].call_args_list]
            self.assertIn(['git', 'config', '--local', 'user.name', 'OpenIG831T contributors'], commands)
            self.assertIn(['git', 'config', '--local', 'user.email', ''], commands)
            self.assertTrue(all(c.args[1] == B for c in patches['wait_ci'].call_args_list))
            calls = patches['verify_clone'].call_args_list
            self.assertEqual(calls[-1].args[1], B); self.assertTrue(calls[-1].kwargs['anonymous'])
            self.assertFalse(any(c.args[0][:3] in (['gh', 'release', 'create'], ['gh', 'release', 'upload'])
                                 or '--visibility' in c.args[0] for c in patches['run'].call_args_list))
            self.assertTrue(all(c.args[1] == A for c in patches['verify_tag'].call_args_list))
            final = patches['write_state'].call_args.args[0]
            self.assertEqual(final['anonymous_verified_commit'], B)
            self.assertEqual(final['release_commit'], A)


if __name__ == '__main__':
    unittest.main()

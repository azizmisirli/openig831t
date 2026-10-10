#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit, checkpointed private-first publication. Default is an offline plan.

State lives only in .git. Publication never forces a tag, overwrites an asset,
changes an unrelated repository, or runs a device-facing command. A release
commit is immutable; a later report commit is independently checked and cloned.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TAG = 'v0.1.0-research-preview'
PUBLIC_AUTHOR = 'OpenIG831T contributors'
DESCRIPTION = ('Reverse engineering and experimental 5G modem bridge research for the DJI '
               'Cellular Dongle 2 (IG831T): USB, AT, QMI, RAW_IP, FunctionFS, and host compatibility.')
TOPICS = ('dji ig831t cellular-dongle qmi wwan usb functionfs linux-gadget raw-ip qmap '
          'fibocom quectel reverse-engineering embedded-linux 5g modem interoperability').split()
WORKFLOWS = {'CI': '.github/workflows/ci.yml', 'Security scan': '.github/workflows/security-scan.yml',
             'Documentation': '.github/workflows/documentation.yml'}
ASSETS = {'openig831t_source.tar.gz', 'openig831t_documentation.tar.gz', 'manifest.json', 'SHA256SUMS'}
MAX_ASSET = 128 * 1024 * 1024
SHA = re.compile(r'[0-9a-f]{40}')


def run(args, *, cwd=None, check=True, env=None, timeout=1800):
    result = subprocess.run(args, cwd=ROOT if cwd is None else cwd, text=True,
                            capture_output=True, env=env, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError('Command failed: '+str(args[0])+' '+str(args[1] if len(args)>1 else '')+
                           ' (exit '+str(result.returncode)+'). Inspect locally; publication stopped.')
    return result


def gh_json(*args):
    return json.loads(run(['gh', *args]).stdout)


def api_optional(path):
    """Only an explicit HTTP 404 is absence; authentication/transient failures stop."""
    result = run(['gh', 'api', path], check=False)
    if not result.returncode:
        return json.loads(result.stdout)
    if re.search(r'\bHTTP 404\b', result.stderr):
        return None
    raise RuntimeError('GitHub API lookup failed; absence was not established.')


def write_state(state):
    path = ROOT/'.git/openig831t-publication.json'
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as handle:
        os.chmod(temporary, 0o600)
        json.dump(state, handle, indent=2); handle.write('\n'); handle.flush(); os.fsync(handle.fileno())
    os.replace(temporary, path)


def setup_python():
    executable = ROOT/'.venv/bin/python'
    if not executable.exists():
        run([sys.executable, '-m', 'venv', str(ROOT/'.venv')])
    run([str(executable), '-m', 'pip', 'install', '--disable-pip-version-check', '-e', '.[dev]'])
    env = dict(os.environ, PYTHONPATH=str(ROOT/'src'), PYTHONDONTWRITEBYTECODE='1')
    env['PATH'] = str(executable.parent)+os.pathsep+env.get('PATH', '')
    return str(executable), env


def checks(python, env, root=None):
    root = ROOT if root is None else root
    for script, extra in [('check_static.py', []), ('validate_offline.py', []),
                          ('validate_docs.py', []), ('evidence_validator.py', []),
                          ('publication_audit.py', ['--git-objects']), ('scan_secrets.py', [])]:
        run([python, 'scripts/'+script, *extra], cwd=root, env=env)
        print(script+': PASS', flush=True)


def refresh(python, env):
    run([python, 'scripts/evidence_validator.py', '--refresh'], env=env)


def head():
    value = run(['git', 'rev-parse', 'HEAD']).stdout.strip()
    if not SHA.fullmatch(value):
        raise RuntimeError('Expected a GitHub-compatible SHA-1 commit.')
    return value


def publication_git_env():
    # Environment identity overrides take precedence over Git config. Pin both
    # author and committer, including an intentionally empty email, on recovery too.
    env = dict(os.environ)
    env.update(GIT_AUTHOR_NAME=PUBLIC_AUTHOR, GIT_COMMITTER_NAME=PUBLIC_AUTHOR,
               GIT_AUTHOR_EMAIL='', GIT_COMMITTER_EMAIL='', EMAIL='')
    return env


def citation_metadata(url, release_date):
    return {'repository-code': url, 'url': url, 'authors': [{'name': PUBLIC_AUTHOR}],
            'date-released': release_date}


def recover_commit(state):
    """Resolve a crash between git commit and its checkpoint, without another commit."""
    pending = state.get('pending_commit')
    if not pending:
        return
    current = head()
    if current == pending['parent']:
        tree = run(['git', 'write-tree']).stdout.strip()
        if tree != pending['tree']:
            raise RuntimeError('Pending commit index changed; manual local review required.')
        run(['git', 'commit', '-m', pending['message']], env=publication_git_env())
        current = head()
    parent = run(['git', 'rev-parse', current+'^']).stdout.strip()
    tree = run(['git', 'rev-parse', current+'^{tree}']).stdout.strip()
    if parent != pending['parent'] or tree != pending['tree']:
        raise RuntimeError('Pending publication commit cannot be recovered safely.')
    state[pending['key']] = current
    del state['pending_commit']
    write_state(state)


def checkpoint_commit(state, key, message):
    recover_commit(state)
    if state.get(key):
        return state[key]
    inventory = json.loads((ROOT/'PUBLICATION_INVENTORY.json').read_text())
    paths = [r['destination_path'] for r in inventory['included']]
    # Reject staged data outside the curated set, including deletions.
    staged = set(run(['git', 'diff', '--cached', '--name-only', '-z']).stdout.split('\0'))-{''}
    if not staged <= set(paths):
        raise RuntimeError('Unreviewed staged paths are present.')
    run(['git', 'add', '--', *paths])
    parent = head()
    changed = run(['git', 'diff', '--cached', '--quiet'], check=False).returncode
    if changed not in (0, 1):
        raise RuntimeError('Cannot inspect publication index.')
    if not changed:
        state[key] = parent; write_state(state); return parent
    state['pending_commit'] = {'key': key, 'parent': parent,
        'tree': run(['git', 'write-tree']).stdout.strip(), 'message': message}
    write_state(state)
    recover_commit(state)
    return state[key]


def require_clean(expected):
    if head() != expected or run(['git', 'status', '--porcelain', '--untracked-files=normal']).stdout:
        raise RuntimeError('Publication checkpoint differs from the clean local source tree.')
    if run(['git', 'branch', '--show-current']).stdout.strip() != 'main':
        raise RuntimeError('Publication must use the main branch.')


def permit_generated_changes(allowed, expected):
    if head() != expected:
        raise RuntimeError('Interrupted metadata preparation has an unexpected HEAD.')
    changes = run(['git', 'status', '--porcelain', '-z', '--untracked-files=normal']).stdout.split('\0')
    for entry in filter(None, changes):
        if len(entry) < 4 or entry[3:] not in allowed or 'R' in entry[:2] or 'C' in entry[:2]:
            raise RuntimeError('Interrupted metadata preparation has unrelated changes.')


def latest_runs(data, sha):
    latest = {}
    for item in data.get('workflow_runs', []):
        name = item.get('name')
        if (name not in WORKFLOWS or item.get('head_sha') != sha or item.get('head_branch') != 'main'
                or item.get('event') != 'push' or item.get('path', '').split('@')[0] != WORKFLOWS[name]):
            continue
        rank = (item['id'], item.get('run_attempt', 1))
        if name not in latest or rank > (latest[name]['id'], latest[name].get('run_attempt', 1)):
            latest[name] = item
    return latest


def expected_job_names():
    # Fail closed if repository workflow structure changes; no guessed branch contexts.
    import yaml
    expected = {}
    for name, path in WORKFLOWS.items():
        data = yaml.safe_load((ROOT/path).read_text())
        if data['name'] != name:
            raise RuntimeError('Workflow name/path changed; review publisher expectations.')
        names = []
        for job in data['jobs'].values():
            matrix = job.get('strategy', {}).get('matrix')
            if matrix:
                if set(matrix) != {'python'}:
                    raise RuntimeError('Unsupported CI matrix; update publisher after review.')
                names.extend(job['name']+' ('+str(version)+')' for version in matrix['python'])
            else:
                names.append(job['name'])
        expected[name] = set(names)
    return expected


def wait_ci(repo, sha, timeout=1800):
    expected = expected_job_names()
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        data = gh_json('api', f'repos/{repo}/actions/runs?head_sha={sha}&per_page=100')
        latest = latest_runs(data, sha)
        if set(latest) == set(WORKFLOWS) and all(r['status'] == 'completed' for r in latest.values()):
            if any(r['conclusion'] != 'success' for r in latest.values()):
                raise RuntimeError('Newest exact-commit CI failed; no visibility change.')
            result = {}
            for name, item in latest.items():
                jobs = gh_json('api', f'repos/{repo}/actions/runs/{item["id"]}/attempts/'
                               f'{item.get("run_attempt", 1)}/jobs?per_page=100')
                rows = jobs.get('jobs', [])
                if (jobs.get('total_count') != len(rows) or {j['name'] for j in rows} != expected[name]
                        or len(rows) != len(expected[name]) or any(j.get('conclusion') != 'success' for j in rows)):
                    raise RuntimeError('CI jobs missing, skipped or unexpected; no visibility change.')
                result[name] = {'id': item['id'], 'attempt': item.get('run_attempt', 1),
                    'conclusion': 'success', 'url': item['html_url'], 'jobs': sorted(expected[name])}
            return result
        print('Waiting for the three workflows on reviewed commit '+sha[:12], flush=True)
        time.sleep(20)
    raise RuntimeError('Remote CI did not complete within the deadline. Resume later.')


def anonymous_bytes(url, limit):
    """No token, cookie jar, netrc, CLI credentials or proxy environment."""
    if not url.startswith('https://'):
        raise ValueError('HTTPS required')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers={'User-Agent': 'OpenIG831T-publication-verifier'})
    with opener.open(request, timeout=60) as response:
        if not response.geturl().startswith('https://'):
            raise RuntimeError('Non-HTTPS download redirect rejected.')
        raw = response.read(limit+1)
    if len(raw) > limit:
        raise RuntimeError('Remote response exceeds expected bound.')
    return raw


def anonymous_json(url):
    return json.loads(anonymous_bytes(url, 4*1024*1024))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def tree_objects(sha):
    rows = run(['git', 'ls-tree', '-r', '-z', '--full-tree', sha]).stdout.split('\0')
    result = {}
    for row in filter(None, rows):
        metadata, path = row.split('\t', 1)
        mode, kind, object_id = metadata.split()
        if kind != 'blob' or mode not in ('100644', '100755'):
            raise RuntimeError('Release contains a non-ordinary tracked file.')
        result[path] = object_id
    return result


def inspect_archive(path, expected_hashes, git_objects=None):
    """Read only, never extract; reject links, duplicates, traversal and unknown files."""
    found = {}; total = 0
    with tarfile.open(path, 'r:gz') as archive:
        for item in archive:
            parts = PurePosixPath(item.name).parts
            if (not item.isfile() or len(parts) < 2 or parts[0] != 'openig831t'
                    or '..' in parts or item.name.startswith('/') or item.size > 16*1024*1024):
                raise RuntimeError('Unsafe archive member.')
            name = '/'.join(parts[1:])
            if item.name != 'openig831t/'+name:
                raise RuntimeError('Non-canonical archive path.')
            if name in found or name not in expected_hashes:
                raise RuntimeError('Duplicate or unexpected archive member.')
            total += item.size
            if total > MAX_ASSET:
                raise RuntimeError('Expanded archive exceeds bound.')
            raw = archive.extractfile(item).read(item.size+1)
            if len(raw) != item.size or digest(raw) != expected_hashes[name]:
                raise RuntimeError('Archive member hash mismatch.')
            if git_objects is not None:
                blob = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
                if git_objects.get(name) != blob:
                    raise RuntimeError('Archive bytes differ from release commit.')
            found[name] = digest(raw)
    if found != expected_hashes:
        raise RuntimeError('Archive file set mismatch.')


def verify_bundle(output, objects):
    if output.is_symlink() or not output.is_dir():
        raise RuntimeError('Release output must be an ordinary directory.')
    names = {p.name for p in output.iterdir()}
    if names != ASSETS or any(p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_ASSET
                              for p in output.iterdir()):
        raise RuntimeError('Unexpected, missing or unsafe release assets.')
    sums = {}
    for line in (output/'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        if not match or match[2] in sums:
            raise RuntimeError('Invalid or duplicate checksum record.')
        sums[match[2]] = match[1]
    if set(sums) != ASSETS-{'SHA256SUMS'}:
        raise RuntimeError('Checksum file set mismatch.')
    actual = {name: digest((output/name).read_bytes()) for name in ASSETS}
    if any(actual[name] != sha for name, sha in sums.items()):
        raise RuntimeError('Release asset checksum mismatch.')
    manifest = json.loads((output/'manifest.json').read_text())
    if (manifest.get('status') != 'PASS' or manifest.get('sources_changed_during_build') != []
            or manifest.get('archive') != 'openig831t_source.tar.gz'
            or manifest.get('documentation_archive') != 'openig831t_documentation.tar.gz'
            or manifest.get('sha256') != actual['openig831t_source.tar.gz']
            or manifest.get('documentation_sha256') != actual['openig831t_documentation.tar.gz']):
        raise RuntimeError('Release manifest is incomplete or inconsistent.')
    files = manifest['files']; docs = manifest['documentation_files']
    if set(files) != set(objects) or len(docs) != len(set(docs)) or not set(docs) <= set(files):
        raise RuntimeError('Bundle differs from tracked release file set.')
    inspect_archive(output/'openig831t_source.tar.gz', files, objects)
    inspect_archive(output/'openig831t_documentation.tar.gz', {name: files[name] for name in docs}, objects)
    return actual


def verify_tag(repo, sha):
    value = gh_json('api', f'repos/{repo}/git/ref/tags/{TAG}')['object']
    for _ in range(8):
        if value['type'] == 'commit':
            if value['sha'] != sha:
                raise RuntimeError('Existing tag does not match release checkpoint; never overwritten.')
            return
        if value['type'] != 'tag':
            break
        value = gh_json('api', f'repos/{repo}/git/tags/{value["sha"]}')['object']
    raise RuntimeError('Tag cannot be resolved to the reviewed commit.')


def verify_remote_assets(repo, release, hashes, output, anonymous=False):
    if release.get('tag_name') != TAG or release.get('draft') or not release.get('prerelease'):
        raise RuntimeError('Release is not the expected published prerelease.')
    rows = release.get('assets', [])
    if len(rows) != len(hashes) or {r['name'] for r in rows} != set(hashes):
        raise RuntimeError('Release assets differ; no existing assets are overwritten.')
    if any(r.get('state') != 'uploaded' or r['size'] != (output/r['name']).stat().st_size for r in rows):
        raise RuntimeError('Release upload incomplete or size mismatch.')
    if anonymous:
        for row in rows:
            expected_url = f'https://github.com/{repo}/releases/download/{TAG}/{row["name"]}'
            if row['browser_download_url'] != expected_url:
                raise RuntimeError('Unexpected release asset URL.')
            raw = anonymous_bytes(expected_url, row['size'])
            if len(raw) != row['size'] or digest(raw) != hashes[row['name']]:
                raise RuntimeError('Anonymous asset checksum mismatch.')
    elif hashes:
        with tempfile.TemporaryDirectory(prefix='openig831t-assets-') as tmp:
            run(['gh', 'release', 'download', TAG, '--repo', repo, '--dir', tmp])
            found = {p.name: digest(p.read_bytes()) for p in Path(tmp).iterdir() if p.is_file()}
            if found != hashes:
                raise RuntimeError('Authenticated release asset checksum mismatch.')


def add_generated_record(name, purpose):
    path = ROOT/'PUBLICATION_INVENTORY.json'; data = json.loads(path.read_text())
    if name not in {r['destination_path'] for r in data['included']}:
        data['included'].append({'source_path': 'publication-generated/'+name,
            'destination_path': name, 'purpose': purpose, 'origin': 'Original publication metadata',
            'ownership': 'OpenIG831T contributors', 'license': 'Apache-2.0',
            'redaction': 'Public authenticated account only; no credentials', 'sha256': None,
            'publication_decision': 'PUBLIC_ORIGINAL_CODE'})
        data['included'].sort(key=lambda r: r['destination_path'])
        path.write_text(json.dumps(data, indent=2)+'\n')


def write_report(state):
    repo = state['repository']; sha = state['release_commit']; url = 'https://github.com/'+repo
    (ROOT/'PUBLICATION_RESULT.md').write_text(
        '<!-- SPDX-License-Identifier: CC-BY-4.0 -->\n# Publication result\n\n'
        '- State: PUBLIC_RELEASE_VERIFIED; final report-commit checks run after this file is committed.\n'
        f'- GitHub owner: {state["owner"]}\n- Repository: [{repo}]({url})\n- Default branch: main\n'
        f'- Verified immutable release commit: `{sha}`\n- Release: [{TAG}]({url}/releases/tag/{TAG})\n'
        '- Release-commit local gates, newest exact-commit CI, private clean clone: PASS.\n'
        '- Anonymous repository, README, prerelease assets and clean-clone checks: PASS.\n'
        '- Both archives and SHA256SUMS were verified against the tagged Git tree.\n'
        '- The release tag is not moved by this later report commit. The publisher separately verifies '
        'CI and an anonymous clean clone of that final branch head; it records completion locally only '
        'after those checks pass. Consult the Actions runs for that exact HEAD.\n'
        '- Optional repository settings: `'+json.dumps(state.get('settings', {}), sort_keys=True)+'`.\n\n'
        'See [SECURITY_SCAN_REPORT.md](SECURITY_SCAN_REPORT.md) and '
        '[EXCLUSION_MANIFEST.md](EXCLUSION_MANIFEST.md) for scan and curation scope.\n\n'
        'This is an experimental research preview. Candidate hardware, physical gadget operation, '
        'DJI host acceptance and end-to-end 5G replacement remain unverified. '
        'Final direct-versus-bridge verdict remains null.\n')


def anonymous_git_env(home):
    # A fresh home also excludes libcurl .netrc and per-user XDG credential files.
    # An allowlist excludes askpass helpers, credential/proxy and Git overrides.
    allowed = {'PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TMPDIR', 'TMP', 'TEMP', 'SYSTEMROOT'}
    env = {key: value for key, value in os.environ.items() if key in allowed}
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home/'config'), CURL_HOME=str(home),
               GIT_TERMINAL_PROMPT='0', GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
    return env


def verify_clone(repo, sha, python, env, anonymous=False):
    with tempfile.TemporaryDirectory(prefix='openig831t-clone-') as tmp:
        clone = Path(tmp)/'repo'
        if anonymous:
            anonymous_home = Path(tmp)/'home'; anonymous_home.mkdir(mode=0o700)
            run(['git', '-c', 'credential.helper=', '-c', 'http.extraHeader=', 'clone',
                 'https://github.com/'+repo+'.git', str(clone)], env=anonymous_git_env(anonymous_home))
        else:
            run(['gh', 'repo', 'clone', repo, str(clone)])
        if run(['git', 'rev-parse', 'HEAD'], cwd=clone).stdout.strip() != sha:
            raise RuntimeError('Clean clone does not match the expected branch commit.')
        checks(python, dict(env, PYTHONPATH=str(clone/'src')), clone)


def assert_remote_head(repo, sha):
    value = gh_json('api', f'repos/{repo}/git/ref/heads/main')
    if value['object']['type'] != 'commit' or value['object']['sha'] != sha:
        raise RuntimeError('Remote main changed; publication stopped.')


def optional_setting(args):
    result = run(args, check=False)
    if not result.returncode:
        return 'ENABLED'
    if re.search(r'\bHTTP (403|404|422)\b', result.stderr):
        return 'UNAVAILABLE_OR_PERMISSION_DENIED'
    raise RuntimeError('Optional setting failed unexpectedly; resume after inspecting locally.')


def settings(repo, workflows):
    # Exact check-run names obtained from successful jobs, not workflow display names.
    contexts = sorted({job for workflow in workflows.values() for job in workflow['jobs']})
    payload = {'required_status_checks': {'strict': True, 'contexts': contexts}, 'enforce_admins': False,
               'required_pull_request_reviews': {'required_approving_review_count': 1}, 'restrictions': None}
    with tempfile.NamedTemporaryFile('w', suffix='.json') as handle:
        json.dump(payload, handle); handle.flush()
        protection = optional_setting(['gh', 'api', '--method', 'PUT',
            f'repos/{repo}/branches/main/protection', '--input', handle.name])
    privacy = optional_setting(['gh', 'api', '--method', 'PUT', f'repos/{repo}/private-vulnerability-reporting'])
    discussions = optional_setting(['gh', 'api', '--method', 'PATCH', f'repos/{repo}', '-F', 'has_discussions=true'])
    return {'branch_protection': protection, 'private_vulnerability_reporting': privacy,
            'discussions': discussions, 'required_contexts': contexts}


def repository(state, owner):
    if not state.get('repository'):
        for slug in ('openig831t', 'openig831t-research'):
            name = owner+'/'+slug
            if api_optional('repos/'+name) is not None:
                continue
            # Preserve intent before a potentially successful command with a lost response.
            state['repository'] = name; state['creation_pending'] = True; write_state(state)
            break
        else:
            raise RuntimeError('Both approved names are occupied; no existing repository was changed.')
    name = state['repository']
    current = api_optional('repos/'+name)
    if current is None:
        if not state.get('creation_pending'):
            raise RuntimeError('Recorded repository is unavailable; it is not recreated automatically.')
        run(['gh', 'repo', 'create', name, '--private', '--description', DESCRIPTION, '--disable-wiki'])
        current = gh_json('api', 'repos/'+name)
    if current['owner']['login'] != owner or current['full_name'] != name:
        raise RuntimeError('Repository ownership mismatch.')
    if state.get('repository_id') not in (None, current['id']):
        raise RuntimeError('Repository identity changed.')
    if state.get('creation_pending'):
        # This cannot prove remote creation attribution after a lost response. A
        # non-empty/name-raced repository is refused instead of silently adopted.
        if not current['private'] or current['size'] != 0 or current.get('description') != DESCRIPTION:
            raise RuntimeError('Pending repository creation is ambiguous; manual review required.')
        state.update(repository_id=current['id'], creation_pending=False); write_state(state)
    if state.get('repository_id') is None:
        raise RuntimeError('Repository ID checkpoint is missing; manual review required.')
    if not current['private'] and not state.get('visibility_intent'):
        raise RuntimeError('Unexpected public remote; private-first provenance is missing.')
    return current


def publish():
    if not (ROOT/'.git').is_dir():
        raise RuntimeError('A locally reviewed Git history is required first.')
    state_file = ROOT/'.git/openig831t-publication.json'
    state = json.loads(state_file.read_text()) if state_file.exists() else {'format_version': 2}
    if state.get('format_version') != 2:
        raise RuntimeError('Older publication state requires explicit migration; it was not overwritten.')
    recover_commit(state)
    # Finish a locally planned report commit after interruption. It changes only
    # the report/inventory, and the immutable release commit remains untouched.
    # Local gates finish before missing authentication becomes the blocking step.
    python, env = setup_python()
    if state.get('final_report_pending') and not state.get('final_commit'):
        permit_generated_changes({'PUBLICATION_RESULT.md', 'PUBLICATION_INVENTORY.json'}, state['release_commit'])
        write_report(state); refresh(python, env); checks(python, env)
        checkpoint_commit(state, 'final_commit', 'Record verified public research-preview publication')
    expected = state.get('final_commit') or state.get('release_commit')
    if expected:
        require_clean(expected)
    elif state.get('metadata_update_pending'):
        permit_generated_changes({'CITATION.cff', '.github/CODEOWNERS', '.github/FUNDING.yml',
                                  'PUBLICATION_RESULT.md', 'PUBLICATION_INVENTORY.json'}, state['initial_commit'])
        refresh(python, env)
    checks(python, env)
    if run(['gh', 'auth', 'status', '--hostname', 'github.com'], check=False).returncode:
        raise RuntimeError('AUTH_REQUIRED: run gh auth login --hostname github.com --git-protocol https --web --scopes repo,workflow')
    user = gh_json('api', 'user'); owner = user['login']
    if not re.fullmatch(r'[A-Za-z0-9-]+', owner) or state.get('owner', owner) != owner:
        raise RuntimeError('Authenticated account differs from the publication owner.')
    state['owner'] = owner
    initial_remote = repository(state, owner)
    repo = state['repository']; url = 'https://github.com/'+repo
    run(['git', 'config', '--local', 'user.name', PUBLIC_AUTHOR])
    run(['git', 'config', '--local', 'user.email', ''])
    if not state.get('release_commit'):
        state.setdefault('initial_commit', head())
        state['metadata_update_pending'] = True; write_state(state)
        import yaml
        citation = yaml.safe_load((ROOT/'CITATION.cff').read_text())
        state.setdefault('release_date', datetime.date.today().isoformat()); write_state(state)
        citation.update(citation_metadata(url, state['release_date']))
        (ROOT/'CITATION.cff').write_text(yaml.safe_dump(citation, sort_keys=False, allow_unicode=False))
        (ROOT/'.github/CODEOWNERS').write_text('# Public repository owner\n* @'+owner+'\n')
        (ROOT/'PUBLICATION_RESULT.md').write_text(
            '<!-- SPDX-License-Identifier: CC-BY-4.0 -->\n# Publication result\n\n'
            'State: PRIVATE_PREPARATION. Local gates precede this commit. Exact-commit remote CI, '
            'private clone, release assets, public visibility and anonymous checks are pending.\n\n'
            f'Intended repository: [{repo}]({url}). Intended prerelease: `{TAG}`. '
            'No candidate hardware or end-to-end 5G replacement has been validated. Final verdict: null.\n')
        sponsor = run(['gh', 'api', 'graphql', '-f', 'query=query { viewer { hasSponsorsListing } }'], check=False)
        if sponsor.returncode == 0 and json.loads(sponsor.stdout).get('data', {}).get('viewer', {}).get('hasSponsorsListing'):
            (ROOT/'.github/FUNDING.yml').write_text('github: ['+owner+']\n')
            add_generated_record('.github/FUNDING.yml', 'Verified GitHub Sponsors profile')
        refresh(python, env); checks(python, env)
        checkpoint_commit(state, 'release_commit', 'Prepare authenticated research-preview publication')
    sha = state['release_commit']
    expected = state.get('final_commit', sha)
    require_clean(expected)
    remote = run(['git', 'remote', 'get-url', 'origin'], check=False)
    if remote.returncode:
        run(['git', 'remote', 'add', 'origin', url+'.git'])
    elif remote.stdout.strip() != url+'.git':
        raise RuntimeError('Existing origin does not match the recorded new repository.')
    run(['gh', 'auth', 'setup-git', '--hostname', 'github.com'])
    run(['git', 'push', '-u', 'origin', 'main'])
    run(['gh', 'repo', 'edit', repo, '--default-branch', 'main', '--enable-issues',
         '--enable-wiki=false', '--delete-branch-on-merge', '--enable-squash-merge',
         '--enable-merge-commit=false', '--enable-rebase-merge=false', '--add-topic', ','.join(TOPICS)])
    workflows = wait_ci(repo, expected)
    assert_remote_head(repo, expected)
    verify_clone(repo, expected, python, env)
    state['authenticated_clone_verified_commit'] = expected
    if initial_remote['private'] and expected == sha:
        state['release_private_verified_commit'] = sha
    if expected == sha:
        state['release_workflows'] = workflows
    write_state(state)
    output = ROOT/'dist'/('release-'+sha)
    objects = tree_objects(sha)
    if not output.exists():
        # Always build from the immutable commit, even after the report commit exists.
        with tempfile.TemporaryDirectory(prefix='openig831t-release-') as tmp:
            clone = Path(tmp)/'repo'
            run(['git', 'clone', '--no-hardlinks', str(ROOT), str(clone)])
            run(['git', 'checkout', '--detach', sha], cwd=clone)
            run([python, 'scripts/build_bundle.py', '--output', str(output)], cwd=clone,
                env=dict(env, PYTHONPATH=str(clone/'src')))
    hashes = verify_bundle(output, objects)
    if state.get('asset_hashes', hashes) != hashes:
        raise RuntimeError('Release asset checkpoint changed.')
    state['asset_hashes'] = hashes; write_state(state)
    release_path = f'repos/{repo}/releases/tags/{TAG}'
    release = api_optional(release_path)
    if release is None:
        existing_tag = api_optional(f'repos/{repo}/git/ref/tags/{TAG}')
        if existing_tag is not None:
            verify_tag(repo, sha)
        run(['gh', 'release', 'create', TAG, *[str(output/name) for name in sorted(ASSETS)],
             '--repo', repo, '--target', sha, '--prerelease', '--title', 'OpenIG831T v0.1.0 — Research Preview',
             '--notes-file', 'releases/'+TAG+'.md'])
        release = gh_json('api', release_path)
    verify_tag(repo, sha)
    # Recover a partial upload only by adding missing names; never clobber existing bytes.
    existing = release.get('assets', [])
    if len(existing) != len({a['name'] for a in existing}) or not {a['name'] for a in existing} <= ASSETS:
        raise RuntimeError('Unexpected existing assets; no release mutation performed.')
    missing = ASSETS-{a['name'] for a in existing}
    if missing:
        # Before adding anything, verify all present assets against the immutable bytes.
        subset = {name: hashes[name] for name in ASSETS-missing}
        verify_remote_assets(repo, release, subset, output)
        run(['gh', 'release', 'upload', TAG, *[str(output/name) for name in sorted(missing)], '--repo', repo])
        release = gh_json('api', release_path)
    verify_remote_assets(repo, release, hashes, output)
    state['release_assets_verified'] = True; write_state(state)
    # Re-check newest CI and branch/tag immediately before visibility changes.
    workflows = wait_ci(repo, expected); assert_remote_head(repo, expected); verify_tag(repo, sha)
    current = gh_json('api', 'repos/'+repo)
    if state.get('release_private_verified_commit') != sha:
        raise RuntimeError('Private release-clone checkpoint is missing; no visibility change.')
    if current['id'] != state['repository_id']:
        raise RuntimeError('Repository identity changed before visibility transition.')
    if not current['private'] and not state.get('visibility_intent'):
        raise RuntimeError('Remote visibility changed outside the recorded publication transition.')
    if current['private']:
        state['visibility_intent'] = True; write_state(state)
        run(['gh', 'repo', 'edit', repo, '--visibility', 'public', '--accept-visibility-change-consequences'])
    metadata = anonymous_json('https://api.github.com/repos/'+repo)
    if metadata['id'] != state['repository_id'] or metadata['private'] or metadata['default_branch'] != 'main':
        raise RuntimeError('Anonymous repository metadata mismatch.')
    anonymous_json('https://api.github.com/repos/'+repo+'/readme')
    release = anonymous_json('https://api.github.com/'+release_path)
    verify_remote_assets(repo, release, hashes, output, anonymous=True)
    verify_clone(repo, expected, python, env, anonymous=True)
    state['anonymous_verified_commit'] = expected
    state['settings'] = settings(repo, workflows); write_state(state)
    if not state.get('final_commit'):
        state['final_report_pending'] = True; write_state(state)
        write_report(state); refresh(python, env); checks(python, env)
        checkpoint_commit(state, 'final_commit', 'Record verified public research-preview publication')
    final_sha = state['final_commit']
    require_clean(final_sha)
    run([python, 'scripts/publication_audit.py', '--git-objects'], env=env)
    run(['git', 'push', 'origin', 'main'])
    final_workflows = wait_ci(repo, final_sha)
    assert_remote_head(repo, final_sha)
    verify_clone(repo, final_sha, python, env, anonymous=True)
    verify_tag(repo, sha)
    state.update(completed=True, latest_commit=final_sha, final_workflows=final_workflows,
                 anonymous_verified_commit=final_sha, repository_url=url,
                 release_url='https://github.com/'+repo+'/releases/tag/'+TAG)
    write_state(state)
    print(json.dumps(state, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', help='Explicitly publish after local and remote gates')
    args = parser.parse_args()
    if not args.execute:
        print('OFFLINE PLAN: local gates -> auth -> private repository -> immutable release commit -> '
              'CI and clean clone -> verified assets -> public visibility -> anonymous checks -> '
              'report commit -> final exact-commit CI and anonymous clean clone.\n'
              'No network, subprocess, device or filesystem mutation was performed by this plan.')
        return 0
    try:
        publish()
    except (RuntimeError, ValueError, OSError, KeyError, subprocess.TimeoutExpired) as exc:
        # Do not print exception payloads containing local paths, tokens or remote bodies.
        print(str(exc) if isinstance(exc, RuntimeError) else 'Publication stopped: '+type(exc).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

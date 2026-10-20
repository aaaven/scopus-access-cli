"""Append actual publisher runtime versions without changing frozen task files."""
import fcntl
import os
import stat
from pathlib import Path

from . import __version__
from .enrichment import encode
from .errors import ValidationError
from .quota import utc_now
from .security import reject_symlink_components, safe_identifier, validate_sha256


def record_runtime(source, plan, plan_sha256, *, backend, action, parser_version,
                   fetch_code_sha256, parser_code_sha256):
    """Called only after project/task validation; contains control metadata only."""
    if backend not in {'static', 'browser'} or action not in {'execute', 'resume', 'export'}:
        raise ValidationError('Publisher runtime action is invalid.')
    for digest in (plan_sha256, fetch_code_sha256, parser_code_sha256):
        validate_sha256(digest)
    record = {'schema_version': '1.0', 'event': 'publisher_runtime',
              'run_id': safe_identifier(plan['run_id'], field='run_id'),
              'plan_sha256': plan_sha256, 'backend': backend, 'action': action,
              'cli_version': __version__, 'parser_version': parser_version,
              'fetch_code_sha256': fetch_code_sha256, 'parser_code_sha256': parser_code_sha256,
              'recorded_at_utc': utc_now()}
    path = Path(source).absolute().parent / 'runtime.jsonl'
    reject_symlink_components(path)
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND
                         | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValidationError('Publisher runtime log must be a regular private file.')
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        raw = encode(record)
        while raw:
            count = os.write(descriptor, raw)
            if count <= 0:
                raise ValidationError('Publisher runtime log append failed.')
            raw = raw[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

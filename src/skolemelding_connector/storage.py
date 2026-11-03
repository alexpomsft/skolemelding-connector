import fcntl
import json
import os
import stat
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path


class ConnectorError(RuntimeError):
    """A safe, non-sensitive diagnostic suitable for CLI and MCP output."""


def config_dir() -> Path:
    return (
        Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "skolemelding-connector"
    )


def private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ConnectorError("Storage directory must be owned by you and have mode 0700.")


def read_json(path: Path) -> dict:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        raise ConnectorError("Local state is missing; run `skolemelding login` first.") from None
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ConnectorError("Local state must be a private regular file (mode 0600).")
        if info.st_size > 10_000_000:
            raise ConnectorError("Local state exceeds the size limit.")
        try:
            data = json.load(stream)
        except (ValueError, UnicodeError):
            raise ConnectorError("Local state is not valid JSON.") from None
    if not isinstance(data, dict):
        raise ConnectorError("Local state must be a JSON object.")
    return data


def write_json(path: Path, data: dict) -> None:
    private_directory(path.parent)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def locked(path: Path, timeout: float = 65):
    private_directory(path.parent)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ConnectorError("Lock must be a private regular file.")
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ConnectorError("Another connector process is busy; try again.") from None
                time.sleep(0.1)
        yield
    finally:
        # Never unlink a flock inode: waiters may still hold the old inode.
        os.close(fd)

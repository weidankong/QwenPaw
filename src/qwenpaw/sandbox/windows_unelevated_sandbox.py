# -*- coding: utf-8 -*-
"""Windows unelevated sandbox implementation.

``WindowsUnelevatedSandbox`` uses a WRITE_RESTRICTED token derived from
the current process token without requiring administrator privileges.
Write access is gated by a fabricated capability SID; read/execute access
is unrestricted.
"""

from __future__ import annotations

import asyncio
import atexit
import ctypes
import ctypes.wintypes
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import ExecutionResult, SandboxConfig
from .windows_sandbox_base import (
    _PROCESS_INFORMATION,
    _SID_AND_ATTRIBUTES,
    _STARTUPINFOW,
    _WC,
    WindowsSandboxBase,
    _AclEntry,
    _build_shell_command_line,
    _compute_config_fingerprint,
    _create_job_object,
    _create_stdio_pipes,
    _create_well_known_sid,
    _enable_privilege,
    _get_advapi32,
    _get_kernel32,
    _get_logon_sid_bytes,
    _get_python_install_dir,
    _is_admin,
    _is_pid_alive,
    _iter_orphaned_metadata,
    _make_env_block,
    _make_random_cap_sid_string,
    _move_to_failed_cleanup,
    _qwenpaw_state_dir,
    _remove_acl_with_verify_sync,
    _sandbox_file_lock,
    _save_sandbox_metadata,
    _set_default_dacl,
    _set_path_ace,
    _sid_to_string,
    _string_to_sid,
    _verify_acl_present_sync,
    _wait_and_read_process,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Unelevated-specific: ACL Helpers
# ═══════════════════════════════════════════════════════════════════════════


def _add_write_allow_ace(path: str, cap_psid: ctypes.c_void_p) -> bool:
    """Adds an inheritable write-allow ACE for a capability SID on a path.

    Args:
        path: Filesystem path to grant write access to.
        cap_psid: Pointer to the capability SID.

    Returns:
        True if the ACE was set successfully.
    """
    return _set_path_ace(
        path,
        cap_psid,
        _WC.WRITE_ALLOW_MASK,
        _WC.SET_ACCESS,
        inherit=True,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Unelevated-specific: Token Creation
# ═══════════════════════════════════════════════════════════════════════════


def _create_restricted_token(
    h_base_token: ctypes.wintypes.HANDLE,
    cap_sid_string: str,
) -> Tuple[ctypes.wintypes.HANDLE, ctypes.c_void_p]:
    """Creates a WRITE_RESTRICTED token for the unelevated sandbox.

    Restricting SID list: ``[cap_sid, logon_sid, Everyone]``.

    Args:
        h_base_token: Handle to the base process token.
        cap_sid_string: Fabricated capability SID string to gate writes.

    Returns:
        (new_token_handle, cap_psid). Caller must free cap_psid with
        LocalFree after ACL operations complete.

    Raises:
        OSError: If CreateRestrictedToken fails.
    """
    advapi32 = _get_advapi32()
    kernel32 = _get_kernel32()

    logon_sid_bytes = _get_logon_sid_bytes(h_base_token)
    logon_buf = (ctypes.c_ubyte * len(logon_sid_bytes))(*logon_sid_bytes)
    logon_ptr = ctypes.cast(logon_buf, ctypes.c_void_p)

    everyone_bytes = _create_well_known_sid(_WC.WinWorldSid)
    everyone_buf = (ctypes.c_ubyte * len(everyone_bytes))(*everyone_bytes)
    everyone_ptr = ctypes.cast(everyone_buf, ctypes.c_void_p)

    cap_psid = _string_to_sid(cap_sid_string)

    entries = [
        _SID_AND_ATTRIBUTES(Sid=cap_psid, Attributes=0),
        _SID_AND_ATTRIBUTES(Sid=logon_ptr, Attributes=0),
        _SID_AND_ATTRIBUTES(Sid=everyone_ptr, Attributes=0),
    ]
    arr = (_SID_AND_ATTRIBUTES * len(entries))(*entries)

    flags = _WC.DISABLE_MAX_PRIVILEGE | _WC.WRITE_RESTRICTED
    new_token = ctypes.wintypes.HANDLE()
    ok = advapi32.CreateRestrictedToken(
        h_base_token,
        flags,
        0,
        None,
        0,
        None,
        len(entries),
        ctypes.cast(arr, ctypes.c_void_p),
        ctypes.byref(new_token),
    )
    if not ok:
        kernel32.LocalFree(cap_psid)
        raise OSError(
            f"CreateRestrictedToken failed: error={ctypes.get_last_error()}",
        )

    try:
        _set_default_dacl(new_token, [cap_psid, logon_ptr, everyone_ptr])
        if not _enable_privilege(new_token, _WC.SE_CHANGE_NOTIFY_NAME):
            logger.warning("Failed to enable SeChangeNotifyPrivilege on token")
    except Exception:
        kernel32.CloseHandle(new_token)
        kernel32.LocalFree(cap_psid)
        raise

    return new_token, cap_psid


# ═══════════════════════════════════════════════════════════════════════════
# Unelevated-specific: Process Creation
# ═══════════════════════════════════════════════════════════════════════════


def _create_process_as_user(
    h_token: ctypes.wintypes.HANDLE,
    cmd: str,
    cwd: str,
    env: Dict[str, str],
    shell_executable: Optional[str] = None,
) -> Tuple[
    int,
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.HANDLE,
    Optional[ctypes.wintypes.HANDLE],
]:
    """Creates a suspended process under the restricted token, then resumes it.

    Args:
        h_token: Restricted token handle.
        cmd: Command to execute.
        cwd: Working directory for the child process.
        env: Environment variables for the child process.
        shell_executable: Shell binary path.

    Returns:
        (pid, process_handle, stdout_read, stderr_read, job_handle) tuple.

    Raises:
        OSError: If CreateProcessAsUserW fails.
    """
    kernel32 = _get_kernel32()
    advapi32 = _get_advapi32()

    stdout_read, stdout_write, stderr_read, stderr_write = _create_stdio_pipes(
        kernel32,
    )

    si = _STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    si.dwFlags = _WC.STARTF_USESTDHANDLES
    si.hStdInput = None
    si.hStdOutput = stdout_write
    si.hStdError = stderr_write
    si.lpDesktop = "WinSta0\\Default"

    env_block = _make_env_block(env)
    command_line = _build_shell_command_line(cmd, shell_executable)
    cl_buf = ctypes.create_unicode_buffer(command_line)

    pi = _PROCESS_INFORMATION()
    flags = (
        _WC.CREATE_UNICODE_ENVIRONMENT
        | _WC.CREATE_NO_WINDOW
        | _WC.CREATE_SUSPENDED
    )

    ok = advapi32.CreateProcessAsUserW(
        h_token,
        None,
        cl_buf,
        None,
        None,
        True,
        flags,
        ctypes.cast(env_block, ctypes.c_void_p),
        ctypes.c_wchar_p(cwd),
        ctypes.byref(si),
        ctypes.byref(pi),
    )
    err = ctypes.get_last_error() if not ok else 0

    kernel32.CloseHandle(stdout_write)
    kernel32.CloseHandle(stderr_write)

    if not ok:
        kernel32.CloseHandle(stdout_read)
        kernel32.CloseHandle(stderr_read)
        raise OSError(f"CreateProcessAsUserW failed: error={err}")

    h_job = _create_job_object()
    if h_job:
        kernel32.AssignProcessToJobObject(h_job, pi.hProcess)

    ctypes.windll.kernel32.ResumeThread(pi.hThread)
    kernel32.CloseHandle(pi.hThread)

    return (pi.dwProcessId, pi.hProcess, stdout_read, stderr_read, h_job)


# ═══════════════════════════════════════════════════════════════════════════
# Unelevated-specific: Per-instance Metadata and Fingerprinting
# ═══════════════════════════════════════════════════════════════════════════


def _unelevated_sandboxes_dir() -> Path:
    """Directory for per-instance unelevated sandbox metadata."""
    return _qwenpaw_state_dir / "unelevated_sandboxes"


def _save_unelevated_metadata(
    sandbox_name: str,
    cap_sid: str,
    config_fingerprint: str,
    acl_entries: List[_AclEntry],
) -> Path:
    """Persists per-instance metadata for cleanup and reuse.

    Returns:
        Path to the written metadata file.
    """
    meta = {
        "sandbox_id": sandbox_name,
        "cap_sid": cap_sid,
        "config_fingerprint": config_fingerprint,
        "owner_pid": os.getpid(),
        "acl_entries": [
            {
                "path": e.path,
                "access_mode": e.access_mode,
                "sid_type": e.sid_type,
            }
            for e in acl_entries
        ],
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    return _save_sandbox_metadata(
        _unelevated_sandboxes_dir(),
        sandbox_name,
        meta,
    )


def _find_reusable_unelevated(sandbox_name: str) -> Optional[dict]:
    """Looks for existing metadata for a sandbox name.

    Returns:
        Metadata dict if found and parseable, None otherwise.
    """
    meta_file = _unelevated_sandboxes_dir() / f"{sandbox_name}.json"
    if not meta_file.exists():
        return None
    try:
        return json.loads(meta_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


# ═══════════════════════════════════════════════════════════════════════════
# WindowsUnelevatedSandbox
# ═══════════════════════════════════════════════════════════════════════════


class WindowsUnelevatedSandbox(WindowsSandboxBase):
    """Windows sandbox using a WRITE_RESTRICTED token without admin privileges.

    Write operations are gated by a fabricated capability SID; read/execute
    access is unrestricted.  Network is soft-blocked via proxy environment
    variables when ``network_allow`` is empty.  Instances are cached on
    disk and reused across invocations with matching config fingerprints.
    """

    # Read access is unrestricted without an elevated token, so unlike the
    # other Windows backends this one cannot honour deny_paths. Its network
    # "block" is proxy environment variables only (see ``execute``), which a
    # raw socket ignores, so network_allow is never enforced here either --
    # hence the ``_enforced_fields`` override below rather than a plain
    # ``_ENFORCED_FIELDS`` narrowing.
    _ENFORCED_FIELDS = frozenset({"mounts", "shell_executable"})

    _ENFORCEMENT_HINTS = {
        "network_allow": (
            "Without an elevated token there is no WFP rule or capability "
            "SID: a block-all request only sets HTTP(S) proxy variables, "
            "which raw sockets ignore, and a domain allowlist sets nothing "
            "at all. Run as administrator for enforced blocking."
        ),
        "deny_paths": (
            "Sensitive paths are NOT protected from read access; run as "
            "administrator to enable full deny_paths enforcement."
        ),
    }

    def _enforced_fields(self) -> frozenset:
        """Never claim ``network_allow``, unlike the elevated backends.

        Deliberately does not extend ``super()``: the base adds
        ``network_allow`` for the absolute postures because AppContainer
        capability SIDs and WFP rules genuinely block at kernel level. This
        backend has neither, so every network posture is unenforced.
        """
        return self._ENFORCED_FIELDS

    def __init__(self, config: SandboxConfig):
        super().__init__(config)
        self._h_token: Optional[ctypes.wintypes.HANDLE] = None
        self._cap_psid: Optional[ctypes.c_void_p] = None
        self._cap_sid_string: Optional[str] = None
        self._sandbox_name: Optional[str] = None
        self._config_fingerprint: Optional[str] = None
        self._metadata_path: Optional[Path] = None
        self._acl_entries: List[_AclEntry] = []
        self._initialized = False

    async def __aenter__(self):
        await self._initialize()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.stop()

    async def _initialize(self) -> None:
        """Set up token and ACLs (runs once, lazily on first use)."""
        if self._initialized:
            return
        await asyncio.to_thread(self._initialize_sync)
        self._initialized = True

    def _initialize_sync(self) -> None:
        """Acquires or creates a sandbox instance under a file lock.

        Computes a config fingerprint and reuses an existing sandbox if
        ACLs are intact; otherwise creates a new one.
        """
        kernel32 = _get_kernel32()
        advapi32 = _get_advapi32()

        workspace = self._config.workspace_dir
        os.makedirs(workspace, exist_ok=True)

        fingerprint = _compute_config_fingerprint(self._config)
        sandbox_name = f"qwenpaw_u_{fingerprint[:12]}"
        self._config_fingerprint = fingerprint
        self._sandbox_name = sandbox_name

        # File lock ensures only one thread/process at a time can
        # check-then-create for the same sandbox_name.  This prevents
        # concurrent callers from generating different capability SIDs
        # and overwriting each other's metadata.
        with _sandbox_file_lock(sandbox_name):
            self._initialize_locked(
                kernel32,
                advapi32,
                workspace,
                sandbox_name,
                fingerprint,
            )

    def _initialize_locked(
        self,
        kernel32,
        advapi32,
        workspace: str,
        sandbox_name: str,
        fingerprint: str,
    ) -> None:
        """Inner initialization logic, called under the sandbox file lock."""
        # Try to reuse an existing sandbox with the same fingerprint
        meta = _find_reusable_unelevated(sandbox_name)
        if meta is not None:
            cap_sid = meta.get("cap_sid", "")
            if cap_sid and _verify_acl_present_sync(workspace, cap_sid):
                logger.info(
                    "Reusing unelevated sandbox %s (cap_sid=%s)",
                    sandbox_name,
                    cap_sid,
                )
                self._cap_sid_string = cap_sid

                h_base = ctypes.wintypes.HANDLE()
                ok = advapi32.OpenProcessToken(
                    kernel32.GetCurrentProcess(),
                    0x000F01FF,
                    ctypes.byref(h_base),
                )
                if not ok:
                    raise OSError(
                        "OpenProcessToken failed: "
                        f"error={ctypes.get_last_error()}",
                    )
                try:
                    self._h_token, self._cap_psid = _create_restricted_token(
                        h_base,
                        cap_sid,
                    )
                finally:
                    kernel32.CloseHandle(h_base)

                self._acl_entries = [
                    _AclEntry(
                        e["path"],
                        e["access_mode"],
                        e["sid_type"],
                    )
                    for e in meta.get("acl_entries", [])
                ]

                # Update owner_pid in the metadata file
                self._metadata_path = _save_unelevated_metadata(
                    sandbox_name,
                    cap_sid,
                    fingerprint,
                    self._acl_entries,
                )
                return

        # Create a new sandbox instance
        self._cap_sid_string = _make_random_cap_sid_string()
        logger.info(
            "Creating unelevated sandbox %s: cap_sid=%s workspace=%s",
            sandbox_name,
            self._cap_sid_string,
            workspace,
        )

        h_base = ctypes.wintypes.HANDLE()
        ok = advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            0x000F01FF,
            ctypes.byref(h_base),
        )
        if not ok:
            raise OSError(
                f"OpenProcessToken failed: error={ctypes.get_last_error()}",
            )

        try:
            self._h_token, self._cap_psid = _create_restricted_token(
                h_base,
                self._cap_sid_string,
            )
        finally:
            kernel32.CloseHandle(h_base)

        if not _add_write_allow_ace(workspace, self._cap_psid):
            logger.error(
                "Failed to set write ACE on workspace: %s",
                workspace,
            )
        else:
            self._acl_entries.append(
                _AclEntry(workspace, "allow_write", "cap"),
            )

        self._apply_mount_acls(workspace)

        assert self._cap_sid_string is not None
        self._metadata_path = _save_unelevated_metadata(
            sandbox_name,
            self._cap_sid_string,
            fingerprint,
            self._acl_entries,
        )

    def _apply_mount_acls(self, workspace: str) -> None:
        """Applies write-allow ACEs on configured mounts."""
        assert self._cap_psid is not None
        ws_abs = os.path.abspath(workspace)
        for mount in self._config.mounts:
            if not mount.writable:
                continue
            if not os.path.exists(mount.path):
                continue
            mount_path = os.path.abspath(mount.path)
            if mount_path == ws_abs:
                continue
            if _add_write_allow_ace(mount_path, self._cap_psid):
                self._acl_entries.append(
                    _AclEntry(mount_path, "allow_write", "cap"),
                )
            else:
                logger.warning("Failed to set ACE on mount: %s", mount_path)

    async def execute(
        self,
        cmd: str,
        cwd: Optional[str] = None,
    ) -> ExecutionResult:
        """Execute a command inside the sandbox."""
        if not self._initialized:
            await self._initialize()

        effective_cwd = cwd or self._config.workspace_dir
        start = time.monotonic()

        try:
            env = self._build_base_env()

            # Network soft-block via proxy environment variables
            if not self._config.network_allow:
                env["HTTP_PROXY"] = "http://127.0.0.1:9"
                env["HTTPS_PROXY"] = "http://127.0.0.1:9"
                env["NO_PROXY"] = ""
                env["http_proxy"] = "http://127.0.0.1:9"
                env["https_proxy"] = "http://127.0.0.1:9"
                env["no_proxy"] = ""

            assert self._h_token is not None
            _, h_proc, h_stdout, h_stderr, h_job = await asyncio.to_thread(
                _create_process_as_user,
                self._h_token,
                cmd,
                effective_cwd,
                env,
                self._config.shell_executable,
            )
            self._process_handle = h_proc
            self._job_handle = h_job

            exit_code, stdout, stderr, timed_out = await asyncio.to_thread(
                self._wait_and_read,
                h_proc,
                h_stdout,
                h_stderr,
                h_job,
            )

            duration_ms = int((time.monotonic() - start) * 1000)
            violation = self._detect_violation(exit_code, stdout, stderr)

            return ExecutionResult(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                timed_out=timed_out,
                duration_ms=duration_ms,
                sandbox_violation=violation,
            )
        except asyncio.CancelledError:
            await self.stop()
            raise
        except OSError as e:
            duration_ms = int((time.monotonic() - start) * 1000)
            await self.stop()
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=str(e),
                timed_out=False,
                duration_ms=duration_ms,
            )
        finally:
            self._process_handle = None
            self._job_handle = None

    def _wait_and_read(
        self,
        h_proc: ctypes.wintypes.HANDLE,
        h_stdout: ctypes.wintypes.HANDLE,
        h_stderr: ctypes.wintypes.HANDLE,
        h_job: Optional[ctypes.wintypes.HANDLE],
    ) -> Tuple[int, str, str, bool]:
        """Waits for process exit and drains output pipes."""
        return _wait_and_read_process(
            h_proc,
            h_stdout,
            h_stderr,
            self._config.timeout_seconds,
            h_job,
        )

    async def stop(self) -> None:
        """Terminates the child process tree and releases Win32 resources.

        The base termination helper uses ``TerminateJobObject`` when a Job
        Object is available, ensuring that cmd.exe and all of its children
        are stopped together.  If initialization or process creation failed
        before any Win32 resource was acquired, avoid loading ``kernel32``.
        """
        has_resources = (
            self._job_handle is not None
            or self._process_handle is not None
            or self._h_token is not None
            or self._cap_psid is not None
        )
        if not has_resources:
            self._initialized = False
            return

        kernel32 = _get_kernel32()

        self._terminate_process()

        if self._h_token:
            kernel32.CloseHandle(self._h_token)
            self._h_token = None

        if self._cap_psid:
            kernel32.LocalFree(self._cap_psid)
            self._cap_psid = None

        self._initialized = False


# ═══════════════════════════════════════════════════════════════════════════
# Module-level cleanup
# ═══════════════════════════════════════════════════════════════════════════


def _migrate_legacy_state_file() -> None:
    """One-time migration: clean up the legacy single state file."""
    legacy_file = _qwenpaw_state_dir / "unelevated_sandbox_state.json"
    if not legacy_file.exists():
        return
    try:
        state = json.loads(legacy_file.read_text(encoding="utf-8"))
        cap_sid = state.get("cap_sid", "")
        failed_paths: List[str] = []
        if cap_sid:
            all_paths = state.get("acl_paths", []) + state.get(
                "deny_paths",
                [],
            )
            deadline = time.monotonic() + 60.0
            for path in all_paths:
                if os.path.exists(path):
                    if not _remove_acl_with_verify_sync(
                        path,
                        cap_sid,
                        deadline=deadline,
                    ):
                        failed_paths.append(path)
        if failed_paths:
            logger.warning(
                "Legacy migration: failed to remove ACL for SID %s "
                "from %d path(s): %s",
                cap_sid,
                len(failed_paths),
                failed_paths,
            )
        legacy_file.unlink(missing_ok=True)
        logger.info("Migrated legacy unelevated sandbox state file")
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to migrate legacy state file: %s", e)


def shutdown_cleanup() -> None:  # pylint: disable=R0912
    """Best-effort cleanup of unelevated sandbox ACLs on process exit.

    Removes ACEs for orphaned sandboxes whose owner process is dead.
    """
    if sys.platform != "win32":
        return

    _migrate_legacy_state_file()

    sb_dir = _unelevated_sandboxes_dir()
    orphaned = _iter_orphaned_metadata(sb_dir)
    if not orphaned:
        return

    t_start = time.monotonic()
    sandboxes_processed = 0

    for meta_file, meta in orphaned:
        cap_sid = meta.get("cap_sid", "")
        if not cap_sid:
            continue

        sandbox_id = meta.get("sandbox_id", cap_sid)
        acl_entries = meta.get("acl_entries", [])
        deadline = time.monotonic() + 60.0
        failed_paths: List[str] = []

        t_sandbox = time.monotonic()
        for entry in acl_entries:
            entry_path = entry.get("path", "")
            if entry_path and os.path.exists(entry_path):
                t_entry = time.monotonic()
                ok = _remove_acl_with_verify_sync(
                    entry_path,
                    cap_sid,
                    deadline=deadline,
                )
                logger.debug(
                    "  [%s] ACL remove [%s] %s: %.2fs",
                    sandbox_id,
                    "OK" if ok else "FAIL",
                    entry_path,
                    time.monotonic() - t_entry,
                )
                if not ok:
                    failed_paths.append(entry_path)

        t_acl_done = time.monotonic()

        if failed_paths:
            logger.warning(
                "Unelevated sandbox cleanup: failed to remove ACL for "
                "SID %s from %d path(s): %s",
                cap_sid,
                len(failed_paths),
                failed_paths,
            )

        logger.info(
            "[%s] ACL removal: %.2fs (%d entries, %d failed)",
            sandbox_id,
            t_acl_done - t_sandbox,
            len(acl_entries),
            len(failed_paths),
        )

        if failed_paths:
            _move_to_failed_cleanup(
                meta,
                meta_file,
                f"ACL removal failed for {len(failed_paths)} path(s)",
            )
        else:
            try:
                meta_file.unlink()
            except OSError:
                pass

        sandboxes_processed += 1

    if sb_dir.exists() and not list(sb_dir.glob("*.json")):
        try:
            sb_dir.rmdir()
        except OSError:
            pass

    if sandboxes_processed > 0:
        logger.info(
            "Unelevated sandbox shutdown_cleanup complete: %d sandbox(es), "
            "%.2fs total",
            sandboxes_processed,
            time.monotonic() - t_start,
        )


atexit.register(shutdown_cleanup)

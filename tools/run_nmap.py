#!/usr/bin/env python3
"""Run one scanner in its own session with bounded TERM -> KILL cleanup."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


KILL_GRACE_SECONDS = 1.0
POLL_SECONDS = 0.05


class Runner:
    def __init__(self, timeout: float, registry: Path, command: list[str]) -> None:
        self.timeout = timeout
        self.registry = registry
        self.command = command
        self.child: subprocess.Popen[bytes] | None = None
        self.child_pid_file: Path | None = None
        self.supervisor_pid_file: Path | None = None
        self.signal_number: int | None = None

    def signal_handler(self, number: int, _frame: object) -> None:
        # Do not perform blocking work from a Python signal handler.  The
        # polling loop notices this promptly and performs one bounded cleanup.
        self.signal_number = number

    def group_signal(self, number: int) -> None:
        child = self.child
        if child is None:
            return
        try:
            # start_new_session=True makes the scanner PID the process-group
            # and session leader, including descendants forked by a mock or
            # by nmap itself.
            os.killpg(child.pid, number)
        except ProcessLookupError:
            pass
        except PermissionError:
            try:
                os.kill(child.pid, number)
            except ProcessLookupError:
                pass

    def group_exists(self) -> bool:
        child = self.child
        if child is None:
            return False
        try:
            # The direct child is reaped before this is called on the normal
            # exit path. killpg(..., 0) therefore checks for descendants left
            # in the original process group without a process-table lookup.
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            # A group that exists but cannot be inspected must still be
            # treated as live so cleanup remains fail-closed.
            return True
        return True

    def cleanup_residual_group(self) -> None:
        """Remove descendants after the direct scanner has already exited."""
        if not self.group_exists():
            return

        self.group_signal(signal.SIGTERM)
        term_deadline = time.monotonic() + KILL_GRACE_SECONDS
        while self.group_exists() and time.monotonic() < term_deadline:
            time.sleep(POLL_SECONDS)

        if self.group_exists():
            # A fork-and-exit descendant may ignore TERM even though the
            # scanner that created it exited successfully. KILL the original
            # group before returning to the worker pool.
            self.group_signal(signal.SIGKILL)
            kill_deadline = time.monotonic() + KILL_GRACE_SECONDS
            while self.group_exists() and time.monotonic() < kill_deadline:
                time.sleep(POLL_SECONDS)

    def wait_for_exit(self, deadline: float) -> int | None:
        assert self.child is not None
        while True:
            return_code = self.child.poll()
            if return_code is not None:
                return return_code
            if self.signal_number is not None or time.monotonic() >= deadline:
                return None
            time.sleep(POLL_SECONDS)

    def terminate_and_reap(self) -> None:
        child = self.child
        if child is None:
            return
        if child.poll() is not None:
            child.wait()
            self.cleanup_residual_group()
            return

        self.group_signal(signal.SIGTERM)
        term_deadline = time.monotonic() + KILL_GRACE_SECONDS
        while child.poll() is None and time.monotonic() < term_deadline:
            time.sleep(POLL_SECONDS)
        if child.poll() is None:
            self.group_signal(signal.SIGKILL)
        else:
            # The direct scanner may have obeyed TERM while a forked
            # descendant ignored it.  Its process group is still the
            # scanner's PID group, so KILL it even after the direct child is
            # reaped.
            self.group_signal(signal.SIGKILL)
        # KILL cannot be ignored.  A short bounded wait reaps the direct
        # child; the process-group KILL above handles its descendants.
        try:
            child.wait(timeout=KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            self.group_signal(signal.SIGKILL)
            child.wait(timeout=KILL_GRACE_SECONDS)

    def run(self) -> int:
        self.registry.mkdir(parents=True, exist_ok=True)
        for number in (signal.SIGTERM, signal.SIGINT):
            signal.signal(number, self.signal_handler)
        # Register the supervisor before spawning anything.  The shell parent
        # can therefore terminate this process even during the launch window.
        self.supervisor_pid_file = self.registry / f"{os.getpid()}.runner.pid"
        self.supervisor_pid_file.write_text(f"{os.getpid()}\n", encoding="ascii")

        try:
            self.child = subprocess.Popen(self.command, start_new_session=True)
            self.child_pid_file = self.registry / f"{os.getpid()}.child.pid"
            self.child_pid_file.write_text(f"{self.child.pid}\n", encoding="ascii")
        except (OSError, ValueError) as exc:
            if self.child is not None:
                self.terminate_and_reap()
            print(f"scanner launch failed: {exc}", file=sys.stderr)
            return 125

        return_code = self.wait_for_exit(time.monotonic() + self.timeout)
        if return_code is not None:
            self.child.wait()
            # Preserve the scanner's actual exit status, but never let a
            # normally exiting scanner leave descendants outside the worker
            # and rate bounds.
            self.cleanup_residual_group()
            if self.signal_number is not None:
                return 128 + self.signal_number
            return return_code

        signal_number = self.signal_number
        was_signal = signal_number is not None
        if was_signal:
            print(
                f"scanner interrupted by signal {signal_number}; terminating process group",
                file=sys.stderr,
            )
        else:
            print("scanner timed out; terminating process group", file=sys.stderr)
        self.terminate_and_reap()
        return (128 + signal_number) if signal_number is not None else 124

    def cleanup(self) -> None:
        if self.child_pid_file is not None:
            try:
                self.child_pid_file.unlink()
            except FileNotFoundError:
                pass
        if self.supervisor_pid_file is not None:
            try:
                self.supervisor_pid_file.unlink()
            except FileNotFoundError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=float, required=True)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.command or args.command[0] != "--":
        parser.error("a scanner command must follow --")
    if args.timeout <= 0:
        parser.error("timeout must be positive")

    runner = Runner(args.timeout, args.registry, args.command[1:])
    try:
        return runner.run()
    finally:
        runner.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())

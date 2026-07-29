"""Mercury command-line interface.

Presentation code parses and projects. Network/task behavior remains in shared
service modules so the later WebUI cannot grow a second implementation.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.metadata
import ipaddress
import platform
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence

from . import DB_SCHEMA_VERSION, MODEL_SCHEMA_VERSION, __version__
from .codec import dumps_document, result_to_wire
from .history import HistoryError, HistoryRecord, HistoryStore, default_history_path
from .models import Disposition, EvidenceKind, TaskState
from .planner import (
    ABSOLUTE_CEILINGS,
    DEFAULT_LIMITS,
    BudgetError,
    ConfirmationError,
    confirmation_phrase,
    authorize_plan,
    preview_plan,
)
from .policy import PolicyError, ScopeGrant, parse_target
from .render import render_history, render_preview, render_result
from .tasks import SyntheticRunner, TaskService

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_POLICY = 3
EXIT_PARTIAL = 4
EXIT_INTERNAL = 70


class CliError(ValueError):
    pass


class MercuryArgumentParser(argparse.ArgumentParser):
    """Keep parser failures inside the stable CLI error boundary."""

    def error(self, message: str) -> None:
        raise CliError(message)


def _version_payload() -> dict[str, object]:
    try:
        psutil_version = importlib.metadata.version("psutil")
    except importlib.metadata.PackageNotFoundError:
        psutil_version = "missing"
    return {
        "mercury": __version__,
        "python": platform.python_version(),
        "psutil": psutil_version,
        "model_schema": MODEL_SCHEMA_VERSION,
        "database_schema": DB_SCHEMA_VERSION,
    }


def _model_payload() -> dict[str, object]:
    return {
        "schema_version": MODEL_SCHEMA_VERSION,
        "dispositions": [value.value for value in Disposition],
        "evidence_kinds": [value.value for value in EvidenceKind],
        "terminal_task_states": [
            TaskState.COMPLETED.value,
            TaskState.FAILED.value,
            TaskState.CANCELLED.value,
        ],
        "semantic_rules": {
            "silence": "inconclusive",
            "tcp_refused": "explicit_negative",
            "udp_application_reply": "direct_positive",
            "unsupported": "unavailable_not_empty_success",
        },
        "absolute_ceilings": ABSOLUTE_CEILINGS.to_wire(),
        "accounting": {
            "rate": "logical attempt starts per second",
            "datagrams": "Mercury-generated UDP datagrams",
            "bytes": "application payload bytes",
            "not_counted": ["kernel retransmissions", "link framing", "TLS overhead"],
        },
    }


def _add_json_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="emit stable JSON instead of human-readable output",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = MercuryArgumentParser(
        prog="mercury",
        description="Evidence-first, authorized network diagnostics.",
    )
    parser.add_argument(
        "--version", action="version", version=f"Mercury {__version__}"
    )
    parser.add_argument("--json", action="store_true", help="emit stable JSON")
    parser.add_argument(
        "--data-path",
        type=Path,
        default=None,
        help=f"history database path (default: {default_history_path()})",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    version_parser = subparsers.add_parser("version", help="show component versions")
    _add_json_option(version_parser)

    model_parser = subparsers.add_parser(
        "model", help="show evidence semantics and absolute ceilings"
    )
    _add_json_option(model_parser)

    plan_parser = subparsers.add_parser(
        "plan", help="canonicalize and cost an active plan without executing it"
    )
    plan_parser.add_argument("targets", nargs="+", help="IP, CIDR, or hostname")
    plan_parser.add_argument(
        "--ports", default="80,443", help="comma-separated ports/ranges"
    )
    plan_parser.add_argument(
        "--transport",
        action="append",
        choices=("tcp", "udp"),
        dest="transports",
        help="transport (repeatable; default tcp)",
    )
    plan_parser.add_argument("--repeat", type=int, default=1)
    plan_parser.add_argument("--payload-bytes", type=int, default=0)
    plan_parser.add_argument(
        "--payload-sha256",
        help="approved custom UDP payload SHA-256 (raw payload is never persisted)",
    )
    plan_parser.add_argument(
        "--payload-profile",
        help="fixed built-in payload profile identifier",
    )
    plan_parser.add_argument("--datagrams", type=int, default=1)
    plan_parser.add_argument(
        "--authorized",
        action="store_true",
        help="attest that every non-loopback target is authorized",
    )
    plan_parser.add_argument(
        "--scope",
        action="append",
        default=[],
        help="authorized IP/CIDR (repeatable)",
    )
    plan_parser.add_argument(
        "--name",
        action="append",
        default=[],
        help="authorized hostname (repeatable)",
    )
    plan_parser.add_argument("--purpose", default="interactive diagnosis")
    plan_parser.add_argument("--custom-udp", action="store_true")
    plan_parser.add_argument(
        "--absolute-limits",
        action="store_true",
        help="preview using absolute rather than normal limits",
    )
    _add_json_option(plan_parser)

    history_parser = subparsers.add_parser("history", help="inspect local history")
    history_subparsers = history_parser.add_subparsers(
        dest="history_command", required=True
    )
    history_list = history_subparsers.add_parser("list", help="list recent tasks")
    history_list.add_argument("--limit", type=int, default=50)
    _add_json_option(history_list)
    history_show = history_subparsers.add_parser("show", help="show a task")
    history_show.add_argument("task_id")
    _add_json_option(history_show)

    task_parser = subparsers.add_parser(
        "task", help=argparse.SUPPRESS, description="Offline developer tasks"
    )
    task_subparsers = task_parser.add_subparsers(dest="task_command", required=True)
    synthetic = task_subparsers.add_parser(
        "synthetic", help="run bounded offline lifecycle work"
    )
    synthetic.add_argument("--steps", type=int, default=3)
    synthetic.add_argument("--delay", type=float, default=0.0)
    synthetic.add_argument("--cancel-after", type=float)
    _add_json_option(synthetic)

    return parser


def _parse_ports(value: str) -> tuple[int, ...]:
    if len(value) > 1_000_000:
        raise CliError("port expression is too long")
    ports: set[int] = set()
    for component in value.split(","):
        component = component.strip()
        if not component:
            raise CliError("empty port expression")
        if "-" in component:
            start_text, separator, end_text = component.partition("-")
            if not separator or not start_text.isdecimal() or not end_text.isdecimal():
                raise CliError(f"invalid port range {component!r}")
            start, end = int(start_text), int(end_text)
            if start > end:
                raise CliError(f"descending port range {component!r}")
            if not 1 <= start <= end <= 65_535:
                raise CliError(f"port range {component!r} is outside 1..65535")
            ports.update(range(start, end + 1))
        else:
            if not component.isdecimal():
                raise CliError(f"invalid port {component!r}")
            port = int(component)
            if not 1 <= port <= 65_535:
                raise CliError(f"port {port} is outside 1..65535")
            ports.add(port)
        if len(ports) > 65_535:
            raise CliError("too many distinct ports")
    return tuple(sorted(ports))


def _scope_from_args(
    args: argparse.Namespace,
    *,
    ports: tuple[int, ...],
    transports: tuple[str, ...],
) -> ScopeGrant:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in args.scope:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise CliError(f"invalid --scope {value!r}") from exc
    # Exact literal/network targets are safe to copy into the declared envelope;
    # hostnames still need explicit resolved-address --scope values.
    for value in args.targets:
        target = parse_target(value)
        if target.address is not None:
            networks.append(
                ipaddress.ip_network(
                    f"{target.address}/{32 if target.address.version == 4 else 128}"
                )
            )
        elif target.network is not None:
            networks.append(target.network)
    names = list(args.name)
    names.extend(
        target.hostname
        for target in (parse_target(value) for value in args.targets)
        if target.hostname is not None
    )
    return ScopeGrant(
        networks=tuple(networks),
        hostnames=tuple(names),
        ports=ports,
        transports=transports,
        attested=bool(args.authorized),
        purpose=args.purpose,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
    )


def _history_record_wire(record: HistoryRecord) -> dict[str, object]:
    return {
        "task_id": record.task_id,
        "task_kind": record.task_kind,
        "state": record.state.value,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "request": record.request,
        "plan": record.plan,
        "result": result_to_wire(record.result) if record.result else None,
    }


def _emit(value: object, human: str, *, as_json: bool) -> None:
    print(dumps_document(value, pretty=True) if as_json else human)


async def _run_synthetic(
    args: argparse.Namespace, history: HistoryStore
) -> tuple[object, str, int]:
    if not 1 <= args.steps <= DEFAULT_LIMITS.max_ports:
        raise CliError(
            f"--steps must be within 1..{DEFAULT_LIMITS.max_ports}"
        )
    preview = preview_plan(
        target_values=("127.0.0.1",),
        ports=range(1, args.steps + 1),
        transports=("tcp",),
        grant=ScopeGrant(networks=()),
        profile="synthetic-v1",
    )
    plan = authorize_plan(preview)
    service = TaskService(history)
    task_id = service.submit(
        plan,
        SyntheticRunner(delay_s=args.delay),
        task_kind="synthetic",
        requested_config={
            "steps": args.steps,
            "delay_s": args.delay,
            "network_io": False,
        },
    )
    if args.cancel_after is not None:
        if args.cancel_after < 0:
            raise CliError("--cancel-after cannot be negative")

        async def cancel_later() -> None:
            await asyncio.sleep(args.cancel_after)
            service.cancel(task_id)

        asyncio.create_task(cancel_later())
    result = await service.wait(task_id)
    exit_code = (
        EXIT_OK
        if result.state is TaskState.COMPLETED
        else EXIT_PARTIAL
        if result.state is TaskState.CANCELLED
        else EXIT_FAILED
    )
    return result_to_wire(result), render_result(result), exit_code


def _dispatch(args: argparse.Namespace) -> int:
    as_json = bool(getattr(args, "json", False))
    if args.command == "version":
        payload = _version_payload()
        human = "\n".join(f"{key}: {value}" for key, value in payload.items())
        _emit(payload, human, as_json=as_json)
        return EXIT_OK
    if args.command == "model":
        payload = _model_payload()
        _emit(
            payload,
            (
                f"Mercury model schema {MODEL_SCHEMA_VERSION}\n"
                f"Dispositions: {', '.join(payload['dispositions'])}\n"
                "Silence remains inconclusive."
            ),
            as_json=as_json,
        )
        return EXIT_OK
    if args.command == "plan":
        ports = _parse_ports(args.ports)
        transports = tuple(args.transports or ("tcp",))
        grant = _scope_from_args(args, ports=ports, transports=transports)
        preview = preview_plan(
            target_values=args.targets,
            ports=ports,
            transports=transports,
            grant=grant,
            repeats=args.repeat,
            payload_bytes_per_attempt=args.payload_bytes,
            datagrams_per_udp_attempt=args.datagrams,
            limits=ABSOLUTE_CEILINGS if args.absolute_limits else DEFAULT_LIMITS,
            custom_udp_payload=args.custom_udp,
            payload_sha256=args.payload_sha256,
            payload_profile=args.payload_profile,
        )
        payload = preview.to_wire()
        payload["confirmation_examples"] = [
            confirmation_phrase(kind, preview.digest)
            for kind in preview.required_confirmations
        ]
        _emit(payload, render_preview(preview), as_json=as_json)
        return EXIT_OK
    if args.command == "history":
        with HistoryStore(args.data_path) as history:
            if args.history_command == "list":
                records = history.list_tasks(limit=args.limit)
                _emit(
                    [_history_record_wire(record) for record in records],
                    render_history(records),
                    as_json=as_json,
                )
                return EXIT_OK
            record = history.get_task(args.task_id)
            if record is None:
                raise CliError(f"history task {args.task_id!r} was not found")
            payload = _history_record_wire(record)
            human = (
                render_result(record.result)
                if record.result is not None
                else f"Task {record.task_id} [{record.state.value}] has no result."
            )
            _emit(payload, human, as_json=as_json)
            return EXIT_OK
    if args.command == "task" and args.task_command == "synthetic":
        with HistoryStore(args.data_path) as history:
            payload, human, exit_code = asyncio.run(_run_synthetic(args, history))
            _emit(payload, human, as_json=as_json)
            return exit_code
    raise CliError("unsupported command")


def _error_payload(category: str, message: str) -> str:
    return dumps_document({"error": {"category": category, "message": message}})


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(argv) if argv is not None else sys.argv[1:]
    as_json = "--json" in arguments
    try:
        parser = build_parser()
        args = parser.parse_args(arguments)
        return _dispatch(args)
    except (PolicyError, BudgetError, ConfirmationError) as exc:
        message = _error_payload("policy", str(exc))
        print(message if as_json else f"mercury: policy: {exc}", file=sys.stderr)
        return EXIT_POLICY
    except (CliError, HistoryError, ValueError) as exc:
        message = _error_payload("input", str(exc))
        print(message if as_json else f"mercury: input: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        message = _error_payload("cancelled", "interrupted by operator")
        print(
            message if as_json else "mercury: cancelled: interrupted by operator",
            file=sys.stderr,
        )
        return EXIT_PARTIAL
    except Exception as exc:  # CLI trust boundary; --debug can be added if needed
        message = f"{type(exc).__name__}: {exc}"
        print(
            _error_payload("internal", message)
            if as_json
            else f"mercury: internal: {message}",
            file=sys.stderr,
        )
        return EXIT_INTERNAL


__all__ = [
    "EXIT_FAILED",
    "EXIT_INTERNAL",
    "EXIT_OK",
    "EXIT_PARTIAL",
    "EXIT_POLICY",
    "EXIT_USAGE",
    "MercuryArgumentParser",
    "build_parser",
    "main",
]

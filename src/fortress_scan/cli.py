from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Set, Tuple

from . import __version__
from .core import baseline as baseline_module
from .core.config import (
    Config,
    ConfigError,
    build_config,
    coverage_reductions,
    find_config_file,
    load_config_file,
)
from .core.model import ScanNotice, ScanResult, parse_confidence, parse_severity
from .core.registry import all_rules, rules_digest
from .report import (
    ConsoleReporter,
    rules_catalogue,
    supports_color,
    to_json,
    to_markdown,
    to_sarif,
)
from .security import paths as safe_paths
from .security import runtime as sandbox
from .security import text as safe_text

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3

_FORMATS = ("console", "json", "sarif", "markdown")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fortress-scan",
        description=(
            "Tìm lỗ hổng code injection trong mã nguồn bằng phân tích luồng dữ liệu tĩnh. "
            "Fortress Scan không bao giờ import, thực thi hay gửi đi mã nguồn mà nó kiểm tra."
        ),
        epilog=(
            "Mã thoát: 0 sạch, 1 có phát hiện từ mức --fail-on trở lên, 2 sai cách dùng, "
            "3 lỗi nội bộ."
        ),
    )
    parser.add_argument(
        "target", nargs="?", default=".", help="tệp hoặc thư mục cần quét (mặc định: .)"
    )
    parser.add_argument("--version", action="version", version="fortress-scan %s" % __version__)

    output = parser.add_argument_group("kết quả")
    output.add_argument(
        "-f", "--format", choices=_FORMATS, default="console", help="định dạng báo cáo"
    )
    output.add_argument("-o", "--output", help="ghi báo cáo ra tệp thay vì in ra màn hình")
    output.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="hiện đường đi của dữ liệu và cách khắc phục",
    )
    output.add_argument("--no-color", action="store_true", help="tắt màu ANSI")
    output.add_argument(
        "--quiet", action="store_true", help="không in báo cáo, chỉ lấy mã thoát"
    )

    selection = parser.add_argument_group("lọc kết quả")
    selection.add_argument(
        "--min-severity",
        metavar="MUC",
        help="bỏ qua phát hiện dưới mức này (info, low, medium, high, critical)",
    )
    selection.add_argument(
        "--min-confidence",
        metavar="MUC",
        help="bỏ qua phát hiện dưới độ tin cậy này (low, medium, high, certain)",
    )
    selection.add_argument(
        "--fail-on",
        metavar="MUC",
        help="thoát khác 0 khi có phát hiện đạt mức này (mặc định: medium)",
    )
    selection.add_argument(
        "--exit-zero", action="store_true", help="luôn thoát 0 kể cả khi có phát hiện"
    )
    selection.add_argument(
        "--disable", metavar="RULE", action="append", default=[], help="tắt một rule theo mã"
    )
    selection.add_argument(
        "--enable",
        metavar="RULE",
        action="append",
        default=[],
        help="chỉ chạy những rule được liệt kê",
    )
    selection.add_argument(
        "--exclude",
        metavar="GLOB",
        action="append",
        default=[],
        help="bỏ qua đường dẫn khớp mẫu kiểu gitignore",
    )
    selection.add_argument(
        "--include",
        metavar="GLOB",
        action="append",
        default=[],
        help="chỉ quét đường dẫn khớp mẫu kiểu gitignore",
    )

    behaviour = parser.add_argument_group("hành vi")
    behaviour.add_argument("--config", help="đường dẫn tới tệp cấu hình JSON")
    behaviour.add_argument(
        "--no-config", action="store_true", help="bỏ qua mọi tệp cấu hình"
    )
    behaviour.add_argument(
        "--baseline", help="ẩn những phát hiện đã có trong tệp baseline này"
    )
    behaviour.add_argument(
        "--write-baseline",
        metavar="DUONG_DAN",
        help="ghi các phát hiện hiện tại ra tệp baseline",
    )
    behaviour.add_argument(
        "--jobs", type=int, metavar="N", help="số luồng xử lý song song (mặc định: 1)"
    )
    behaviour.add_argument(
        "--max-file-size", type=int, metavar="BYTE", help="bỏ qua tệp lớn hơn mức này"
    )
    behaviour.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="đi theo liên kết nằm trong thư mục quét (mặc định tắt)",
    )
    behaviour.add_argument(
        "--no-inline-suppressions",
        action="store_true",
        help="bỏ qua các chú thích fortress-scan: ignore trong mã được quét",
    )
    behaviour.add_argument(
        "--no-ignore-files",
        action="store_true",
        help="không đọc các tệp .fortress-scanignore trong mã được quét",
    )
    behaviour.add_argument(
        "--no-vcs-ignore", action="store_true", help="không đọc các tệp .gitignore"
    )
    behaviour.add_argument(
        "--include-env-sources",
        action="store_true",
        help="coi biến môi trường và tham số dòng lệnh là dữ liệu không tin cậy",
    )

    information = parser.add_argument_group("thông tin")
    information.add_argument(
        "--list-rules", action="store_true", help="in danh mục rule rồi thoát"
    )
    information.add_argument(
        "--rules-digest", action="store_true", help="in mã băm của bộ rule rồi thoát"
    )
    return parser


def _prepare_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError, AttributeError):
            pass


def main(argv: Optional[Sequence[str]] = None) -> int:
    _prepare_streams()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        sys.stdout.write(rules_catalogue())
        return EXIT_CLEAN
    if args.rules_digest:
        sys.stdout.write(rules_digest() + "\n")
        return EXIT_CLEAN

    sandbox.engage()
    for warning in sandbox.elevated_privilege_warnings():
        sys.stderr.write("fortress-scan: cảnh báo: %s\n" % warning)

    try:
        config, config_notices = _resolve_config(args)
    except (ConfigError, ValueError) as exc:
        sys.stderr.write("fortress-scan: %s\n" % exc)
        return EXIT_USAGE
    if config_notices:
        sys.stderr.write("fortress-scan: cảnh báo: %s\n" % config_notices[0])
        for detail in config_notices[1:]:
            sys.stderr.write("    %s\n" % detail)

    baseline_fingerprints: Set[str] = set()
    if args.baseline:
        try:
            baseline_fingerprints = baseline_module.load(Path(args.baseline))
        except baseline_module.BaselineError as exc:
            sys.stderr.write("fortress-scan: %s\n" % exc)
            return EXIT_USAGE

    output_path: Optional[Path] = None
    if args.output:
        try:
            output_path = safe_paths.validate_output_path(args.output)
        except safe_paths.PathConfinementError as exc:
            sys.stderr.write("fortress-scan: %s\n" % exc)
            return EXIT_USAGE

    baseline_path: Optional[Path] = None
    if args.write_baseline:
        try:
            baseline_path = safe_paths.validate_output_path(args.write_baseline)
        except safe_paths.PathConfinementError as exc:
            sys.stderr.write("fortress-scan: %s\n" % exc)
            return EXIT_USAGE

    from .core.engine import scan

    scan_notices = (
        [
            ScanNotice(
                kind="project-config",
                summary=config_notices[0],
                details=tuple(config_notices[1:]),
            )
        ]
        if config_notices
        else []
    )

    try:
        result = scan(args.target, config, baseline_fingerprints, scan_notices)
    except safe_paths.PathConfinementError as exc:
        sys.stderr.write("fortress-scan: %s\n" % exc)
        return EXIT_USAGE
    except KeyboardInterrupt:
        sys.stderr.write("fortress-scan: đã dừng theo yêu cầu\n")
        return EXIT_INTERNAL
    except Exception as exc:
        sys.stderr.write("fortress-scan: lỗi nội bộ: %s: %s\n" % (type(exc).__name__, exc))
        return EXIT_INTERNAL

    if baseline_path is not None:
        try:
            baseline_path.write_text(baseline_module.serialize(result.findings), encoding="utf-8")
        except OSError as exc:
            sys.stderr.write("fortress-scan: không ghi được baseline: %s\n" % exc)
            return EXIT_USAGE

    if not args.quiet:
        try:
            _emit(result, args, output_path)
        except OSError as exc:
            sys.stderr.write("fortress-scan: không ghi được báo cáo: %s\n" % exc)
            return EXIT_USAGE

    if args.exit_zero:
        return EXIT_CLEAN
    highest = result.highest_severity()
    if highest is not None and highest >= config.fail_on:
        return EXIT_FINDINGS
    return EXIT_CLEAN


def _emit(result: ScanResult, args: argparse.Namespace, output_path: Optional[Path]) -> None:
    if args.format == "console" and output_path is None:
        reporter = ConsoleReporter(
            sys.stdout,
            color=supports_color(sys.stdout) and not args.no_color,
            verbose=args.verbose,
        )
        reporter.render(result)
        return

    if args.format == "json":
        payload = to_json(result, __version__)
    elif args.format == "sarif":
        payload = to_sarif(result, __version__)
    else:
        payload = to_markdown(result, __version__)

    if output_path is None:
        sys.stdout.write(payload)
        return
    output_path.write_text(payload, encoding="utf-8")
    sys.stderr.write("fortress-scan: đã ghi báo cáo vào %s\n" % output_path)


def _config_from_file(args: argparse.Namespace) -> Tuple[Config, Tuple[str, ...]]:
    """Nạp tệp cấu hình, kèm cảnh báo nếu nó tự tìm thấy trong cây bị quét."""
    config = Config()
    if args.no_config:
        return config, ()
    if args.config:
        source = Path(args.config)
        if not source.is_file():
            raise ConfigError("không tìm thấy tệp cấu hình: %s" % args.config)
        return build_config(load_config_file(source), config), ()
    target = Path(args.target)
    source = find_config_file(target if target.exists() else Path("."))
    if source is None:
        return config, ()
    data = load_config_file(source)
    return build_config(data, config), _project_config_notices(source, data)


def _resolve_config(args: argparse.Namespace) -> Tuple[Config, Tuple[str, ...]]:
    config, notices = _config_from_file(args)

    known = {rule.id for rule in all_rules()}
    disabled = tuple(item.strip().upper() for item in args.disable)
    enabled = tuple(item.strip().upper() for item in args.enable)
    for rule_id in disabled + enabled:
        if rule_id not in known:
            raise ConfigError("không có rule với mã: %s" % rule_id)

    overrides = {}
    if args.min_severity:
        overrides["min_severity"] = parse_severity(args.min_severity)
    if args.min_confidence:
        overrides["min_confidence"] = parse_confidence(args.min_confidence)
    if args.fail_on:
        overrides["fail_on"] = parse_severity(args.fail_on)
    if disabled:
        overrides["disabled_rules"] = tuple(config.disabled_rules) + disabled
    if enabled:
        overrides["enabled_rules"] = tuple(config.enabled_rules) + enabled
    if args.exclude:
        overrides["exclude_patterns"] = tuple(config.exclude_patterns) + tuple(args.exclude)
    if args.include:
        overrides["include_patterns"] = tuple(config.include_patterns) + tuple(args.include)
    if args.jobs is not None:
        if args.jobs < 1:
            raise ConfigError("--jobs phải ít nhất bằng 1")
        overrides["jobs"] = args.jobs
    if args.max_file_size is not None:
        if args.max_file_size < 1:
            raise ConfigError("--max-file-size phải là số dương")
        overrides["max_file_bytes"] = args.max_file_size
    if args.follow_symlinks:
        overrides["follow_symlinks"] = True
    if args.no_inline_suppressions:
        overrides["honor_inline_suppressions"] = False
    if args.no_ignore_files:
        overrides["respect_ignore_files"] = False
    if args.no_vcs_ignore:
        overrides["respect_vcs_ignore"] = False
    if args.include_env_sources:
        overrides["include_low_signal_sources"] = True
    return config.with_overrides(**overrides), notices


def _project_config_notices(source: Path, data: Dict[str, Any]) -> Tuple[str, ...]:
    """Cấu hình tự tìm thấy trong cây bị quét có thể làm báo cáo sạch đi.

    Khi quét mã của người khác thì tệp này do họ viết, nên nó phải hiện ra --
    "sạch" mà không nói vì sao sạch chính là thứ tạo ra false confidence.
    """
    reductions = coverage_reductions(data)
    if not reductions:
        return ()
    # Giữ chuỗi ở dạng thuần, không nhúng sẵn dấu đầu dòng: chúng còn đi vào
    # JSON, SARIF và Markdown, nơi mỗi định dạng tự lo cách trình bày.
    lines = [
        "%s trong cây được quét đã thu hẹp phạm vi quét:"
        % safe_text.display_path(str(source))
    ]
    lines.extend(reductions)
    lines.append("chạy lại với --no-config nếu không tin tệp cấu hình này")
    return tuple(lines)


if __name__ == "__main__":
    sys.exit(main())

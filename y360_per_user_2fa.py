#!/usr/bin/env python3
"""Mass management of per-user mandatory 2FA in Yandex 360.

The script uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import re
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


API_BASE = "https://api360.yandex.net"
CSV_FIELDS = ("UID", "login", "email")
RESULT_FIELDS = (
    "UID",
    "login",
    "email",
    "requested_state",
    "status",
    "http_status",
    "verified_state",
    "message",
)
TRANSIENT_HTTP_CODES = {429, 500, 502, 503, 504}
MAX_PER_PAGE = 1000
DEFAULT_WORKERS = 4
DEFAULT_TIMEOUT = 30.0
DEFAULT_RETRIES = 5
PRINT_LOCK = threading.Lock()


class AppError(Exception):
    """Expected error that can be shown without a traceback."""


class ApiError(AppError):
    def __init__(self, status: int | None, message: str, transient: bool = False):
        super().__init__(message)
        self.status = status
        self.transient = transient


@dataclass(frozen=True)
class UserSelection:
    uid: str
    login: str
    email: str
    row_number: int


@dataclass(frozen=True)
class ChangeResult:
    uid: str
    login: str
    email: str
    requested_state: bool
    status: str
    http_status: int | None
    verified_state: bool | None
    message: str


def eprint(message: str) -> None:
    print(message, file=sys.stderr)


def script_dir() -> Path:
    return Path(__file__).resolve().parent


def timestamp() -> str:
    return datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")


def bool_text(value: bool) -> str:
    return "true" if value else "false"


def load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError as exc:
        raise AppError(f"Не удалось прочитать {path}: {exc}") from exc

    for number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise AppError(
                f"Некорректная строка {number} в {path}: ожидается ИМЯ=значение"
            )
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'\"', "'"}:
            value = value[1:-1]
        values[key] = value
    return values


def get_credentials(env_file: Path) -> tuple[str, str]:
    file_values = load_dotenv(env_file)
    token = os.environ.get("OAUTH_TOKEN", file_values.get("OAUTH_TOKEN", "")).strip()
    org_id = os.environ.get("ORG_ID", file_values.get("ORG_ID", "")).strip()
    if not token:
        raise AppError("Не указан OAUTH_TOKEN: задайте переменную окружения или .env")
    if not org_id:
        raise AppError("Не указан ORG_ID: задайте переменную окружения или .env")
    if not re.fullmatch(r"\d+", org_id):
        raise AppError("ORG_ID должен состоять только из цифр")
    return token, org_id


def extract_api_message(body: bytes, fallback: str) -> str:
    if not body:
        return fallback
    text = body.decode("utf-8", errors="replace")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return text[:500].replace("\n", " ").strip() or fallback
    if isinstance(data, dict):
        message = data.get("message") or data.get("error_description") or data.get("error")
        if message:
            return str(message)[:500]
    return fallback


def retry_delay(attempt: int, retry_after: str | None) -> float:
    if retry_after:
        try:
            return min(max(float(retry_after), 0.0), 60.0)
        except ValueError:
            pass
    return min(2**attempt + random.uniform(0.0, 0.5), 30.0)


def api_request(
    method: str,
    url: str,
    token: str,
    *,
    payload: dict[str, Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {
        "Authorization": f"OAuth {token}",
        "Accept": "application/json",
        "User-Agent": "yandex360-per-user-2fa/1.0",
    }
    if data is not None:
        headers["Content-Type"] = "application/json; charset=utf-8"

    for attempt in range(retries + 1):
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read()
                if not body:
                    return {}
                decoded = json.loads(body.decode("utf-8"))
                if not isinstance(decoded, dict):
                    raise ApiError(response.status, "API вернул JSON неожиданного формата")
                return decoded
        except urllib.error.HTTPError as exc:
            body = exc.read()
            message = extract_api_message(body, exc.reason or f"HTTP {exc.code}")
            transient = exc.code in TRANSIENT_HTTP_CODES
            if transient and attempt < retries:
                time.sleep(retry_delay(attempt, exc.headers.get("Retry-After")))
                continue
            raise ApiError(exc.code, message, transient=transient) from exc
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            reason = getattr(exc, "reason", exc)
            if attempt < retries:
                time.sleep(retry_delay(attempt, None))
                continue
            raise ApiError(None, f"Сетевая ошибка: {reason}", transient=True) from exc
        except json.JSONDecodeError as exc:
            raise ApiError(None, "API вернул некорректный JSON") from exc
    raise ApiError(None, "Запрос не выполнен после повторных попыток", transient=True)


def list_users(token: str, org_id: str, timeout: float, retries: int) -> list[dict[str, Any]]:
    users: list[dict[str, Any]] = []
    page = 1
    while True:
        query = urllib.parse.urlencode({"page": page, "perPage": MAX_PER_PAGE})
        url = f"{API_BASE}/directory/v1/org/{org_id}/users?{query}"
        response = api_request("GET", url, token, timeout=timeout, retries=retries)
        batch = response.get("users")
        if not isinstance(batch, list):
            raise AppError("В ответе API отсутствует массив users")
        users.extend(user for user in batch if isinstance(user, dict))
        pages = response.get("pages")
        if isinstance(pages, int) and pages > 0:
            if page >= pages:
                break
        elif len(batch) < MAX_PER_PAGE:
            break
        page += 1
    return users


def get_domain_2fa(token: str, org_id: str, timeout: float, retries: int) -> dict[str, Any]:
    url = f"{API_BASE}/security/v2/org/{org_id}/domain_2fa"
    return api_request("GET", url, token, timeout=timeout, retries=retries)


def require_per_user_mode(status: dict[str, Any]) -> None:
    enabled = status.get("enabled")
    scope = status.get("scope")
    if enabled is not True or scope != "per_user":
        raise AppError(
            "В организации не включена обязательная 2FA v2 в режиме per_user "
            f"(API вернул enabled={enabled!r}, scope={scope!r}). "
            "Сначала выполните действие domain-enable или настройте режим в Кабинете организации."
        )


def enable_domain_per_user(args: argparse.Namespace, token: str, org_id: str) -> int:
    current = get_domain_2fa(token, org_id, args.timeout, args.retries)
    if current.get("enabled") is True and current.get("scope") == "per_user":
        print("Обязательная 2FA уже включена в режиме per_user.")
        print(json.dumps(current, ensure_ascii=False, indent=2))
        return 0

    print("Текущая настройка организации:")
    print(json.dumps(current, ensure_ascii=False, indent=2))
    if not args.yes:
        phrase = f"ВКЛЮЧИТЬ PER_USER {org_id}"
        entered = input(f"Для изменения режима введите «{phrase}»: ").strip()
        if entered != phrase:
            raise AppError("Операция отменена: контрольная фраза не совпала")

    payload = {
        "duration": args.duration,
        "logoutUsers": args.logout_users,
        "validationMethod": args.validation_method,
        "scope": "per_user",
    }
    url = f"{API_BASE}/security/v2/org/{org_id}/domain_2fa"
    result = api_request(
        "POST", url, token, payload=payload, timeout=args.timeout, retries=args.retries
    )
    require_per_user_mode(result)
    print("Обязательная 2FA включена в режиме per_user.")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def secure_file_permissions(path: Path) -> None:
    if os.name == "posix":
        try:
            path.chmod(0o600)
        except OSError:
            pass


def atomic_write_csv(path: Path, fields: Iterable[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8-sig",
            newline="",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temp_name = stream.name
            writer = csv.DictWriter(
                stream, fieldnames=list(fields), delimiter=";", lineterminator="\n"
            )
            writer.writeheader()
            writer.writerows(rows)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
        secure_file_permissions(path)
    except OSError as exc:
        if temp_name:
            try:
                Path(temp_name).unlink(missing_ok=True)
            except OSError:
                pass
        raise AppError(f"Не удалось записать {path}: {exc}") from exc


def export_users(args: argparse.Namespace, token: str, org_id: str, output: Path) -> tuple[int, int]:
    require_per_user_mode(get_domain_2fa(token, org_id, args.timeout, args.retries))
    users = list_users(token, org_id, args.timeout, args.retries)
    rows: list[dict[str, str]] = []
    excluded = 0
    for user in users:
        if args.exclude_dismissed and user.get("isDismissed") is True:
            excluded += 1
            continue
        if args.exclude_disabled and user.get("isEnabled") is False:
            excluded += 1
            continue
        if args.exclude_robots and user.get("isRobot") is True:
            excluded += 1
            continue
        uid = str(user.get("id", "")).strip()
        login = str(user.get("nickname", "")).strip()
        email = str(user.get("email", "")).strip()
        if not uid or not login:
            excluded += 1
            continue
        rows.append({"UID": uid, "login": login, "email": email})
    atomic_write_csv(output, CSV_FIELDS, rows)
    return len(rows), excluded


def detect_delimiter(sample: str) -> str:
    try:
        return csv.Sniffer().sniff(sample, delimiters=";,\t").delimiter
    except csv.Error:
        return ";"


def read_selection(path: Path) -> list[UserSelection]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            sample = stream.read(8192)
            stream.seek(0)
            reader = csv.DictReader(stream, delimiter=detect_delimiter(sample))
            actual_fields = tuple((field or "").strip() for field in (reader.fieldnames or ()))
            if actual_fields != CSV_FIELDS:
                raise AppError("Некорректные заголовки CSV. Ожидается: " + ";".join(CSV_FIELDS))
            selected: list[UserSelection] = []
            seen_uids: set[str] = set()
            for row_number, row in enumerate(reader, start=2):
                if None in row:
                    raise AppError(f"Строка {row_number}: обнаружены лишние столбцы")
                uid = (row.get("UID") or "").strip()
                login = (row.get("login") or "").strip()
                email = (row.get("email") or "").strip()
                if not any((uid, login, email)):
                    continue
                if not uid or not login:
                    raise AppError(f"Строка {row_number}: UID и login обязательны")
                if not re.fullmatch(r"\d+", uid):
                    raise AppError(f"Строка {row_number}: UID должен состоять только из цифр")
                if uid in seen_uids:
                    raise AppError(f"Строка {row_number}: UID {uid} встречается повторно")
                seen_uids.add(uid)
                selected.append(UserSelection(uid, login, email, row_number))
    except OSError as exc:
        raise AppError(f"Не удалось прочитать {path}: {exc}") from exc
    if not selected:
        raise AppError("В CSV не осталось пользователей для обработки")
    return selected


def validate_against_directory(
    selected: list[UserSelection], current_users: list[dict[str, Any]]
) -> None:
    directory = {
        str(user.get("id", "")).strip(): (
            str(user.get("nickname", "")).strip().casefold(),
            str(user.get("email", "")).strip().casefold(),
        )
        for user in current_users
        if user.get("id") is not None
    }
    errors: list[str] = []
    for item in selected:
        current = directory.get(item.uid)
        if current is None:
            errors.append(f"строка {item.row_number}: UID {item.uid} не найден")
            continue
        current_login, current_email = current
        if current_login != item.login.casefold():
            errors.append(f"строка {item.row_number}: login не соответствует UID {item.uid}")
        elif item.email and current_email != item.email.casefold():
            errors.append(f"строка {item.row_number}: email не соответствует UID {item.uid}")
    if errors:
        preview = "; ".join(errors[:10])
        suffix = f"; еще ошибок: {len(errors) - 10}" if len(errors) > 10 else ""
        raise AppError(f"Предварительная проверка не пройдена: {preview}{suffix}")


def confirm_changes(count: int, target_state: bool) -> None:
    action = "ВКЛЮЧИТЬ" if target_state else "ВЫКЛЮЧИТЬ"
    phrase = f"{action} 2FA {count}"
    print(f"Будет обработано пользователей: {count}; целевое состояние: {bool_text(target_state)}.")
    entered = input(f"Для продолжения введите «{phrase}»: ").strip()
    if entered != phrase:
        raise AppError("Операция отменена: контрольная фраза не совпала")


def get_user_2fa(
    item: UserSelection, token: str, org_id: str, timeout: float, retries: int
) -> bool:
    url = f"{API_BASE}/directory/v1/org/{org_id}/users/{item.uid}/domain_2fa"
    response = api_request("GET", url, token, timeout=timeout, retries=retries)
    state = response.get("is2faEnabled")
    if not isinstance(state, bool):
        raise ApiError(None, "API не вернул логический параметр is2faEnabled")
    return state


def patch_one(
    item: UserSelection,
    target_state: bool,
    verify: bool,
    token: str,
    org_id: str,
    timeout: float,
    retries: int,
) -> ChangeResult:
    query = urllib.parse.urlencode({"is2faEnabled": bool_text(target_state)})
    url = f"{API_BASE}/directory/v1/org/{org_id}/users/{item.uid}/domain_2fa?{query}"
    try:
        api_request("PATCH", url, token, timeout=timeout, retries=retries)
        verified_state: bool | None = None
        if verify:
            verified_state = get_user_2fa(item, token, org_id, timeout, retries)
            if verified_state != target_state:
                return ChangeResult(
                    item.uid,
                    item.login,
                    item.email,
                    target_state,
                    "failed",
                    200,
                    verified_state,
                    "PATCH выполнен, но контрольный GET вернул другое состояние",
                )
        return ChangeResult(
            item.uid,
            item.login,
            item.email,
            target_state,
            "success",
            200,
            verified_state,
            "Персональная 2FA изменена" + (" и проверена" if verify else ""),
        )
    except ApiError as exc:
        return ChangeResult(
            item.uid,
            item.login,
            item.email,
            target_state,
            "failed",
            exc.status,
            None,
            str(exc),
        )


def run_changes(
    selected: list[UserSelection],
    target_state: bool,
    verify: bool,
    token: str,
    org_id: str,
    workers: int,
    timeout: float,
    retries: int,
) -> list[ChangeResult]:
    results_by_uid: dict[str, ChangeResult] = {}
    completed = 0
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="2fa-change") as pool:
        future_map = {
            pool.submit(
                patch_one, item, target_state, verify, token, org_id, timeout, retries
            ): item
            for item in selected
        }
        for future in as_completed(future_map):
            item = future_map[future]
            try:
                result = future.result()
            except Exception as exc:
                result = ChangeResult(
                    item.uid,
                    item.login,
                    item.email,
                    target_state,
                    "failed",
                    None,
                    None,
                    f"Неожиданная ошибка: {exc}",
                )
            results_by_uid[item.uid] = result
            completed += 1
            with PRINT_LOCK:
                print(f"Обработано: {completed}/{len(selected)}", end="\r", flush=True)
    print(" " * 50, end="\r")
    return [results_by_uid[item.uid] for item in selected]


def write_results(path: Path, results: list[ChangeResult]) -> None:
    rows = (
        {
            "UID": result.uid,
            "login": result.login,
            "email": result.email,
            "requested_state": bool_text(result.requested_state),
            "status": result.status,
            "http_status": "" if result.http_status is None else str(result.http_status),
            "verified_state": ""
            if result.verified_state is None
            else bool_text(result.verified_state),
            "message": result.message,
        }
        for result in results
    )
    atomic_write_csv(path, RESULT_FIELDS, rows)


def apply_file(
    args: argparse.Namespace, token: str, org_id: str, input_path: Path
) -> int:
    require_per_user_mode(get_domain_2fa(token, org_id, args.timeout, args.retries))
    selected = read_selection(input_path)
    print("Проверка UID, логинов и адресов по актуальному справочнику...")
    current_users = list_users(token, org_id, args.timeout, args.retries)
    validate_against_directory(selected, current_users)
    target_state = args.state == "enable"

    if args.dry_run:
        print("Проверка завершена успешно. Изменяющие PATCH-запросы не отправлялись.")
        print(
            f"Готово к обработке: {len(selected)}; целевое состояние: {bool_text(target_state)}."
        )
        return 0
    if not args.yes:
        confirm_changes(len(selected), target_state)

    results = run_changes(
        selected,
        target_state,
        args.verify,
        token,
        org_id,
        args.workers,
        args.timeout,
        args.retries,
    )
    result_path = input_path.with_name(f"2fa_change_results_{timestamp()}.csv")
    write_results(result_path, results)
    succeeded = sum(result.status == "success" for result in results)
    failed = len(results) - succeeded
    print("Итоговая сводка:")
    print(f"  Успешно: {succeeded}")
    print(f"  Ошибки: {failed}")
    print(f"  Целевое состояние: {bool_text(target_state)}")
    print(f"  Контрольный GET: {'включен' if args.verify else 'не выполнялся'}")
    print(f"  Отчет: {result_path}")
    return 2 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Массовое управление персональной обязательной 2FA в Яндекс 360."
    )
    parser.add_argument(
        "action",
        nargs="?",
        choices=("interactive", "export", "apply", "status", "domain-enable"),
        default="interactive",
        help="interactive (по умолчанию), export, apply, status или domain-enable",
    )
    parser.add_argument("--file", type=Path, help="Путь к рабочему CSV")
    parser.add_argument(
        "--env-file", type=Path, default=script_dir() / ".env", help="Путь к .env"
    )
    parser.add_argument(
        "--state",
        choices=("enable", "disable"),
        default="enable",
        help="Целевое состояние пользователей; по умолчанию enable",
    )
    parser.add_argument(
        "--workers", type=int, default=DEFAULT_WORKERS, help="Параллельные запросы (1-10)"
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT, help="Тайм-аут HTTP-запроса"
    )
    parser.add_argument(
        "--retries", type=int, default=DEFAULT_RETRIES, help="Повторы временных ошибок"
    )
    parser.add_argument("--dry-run", action="store_true", help="Проверить без изменений")
    parser.add_argument("--yes", action="store_true", help="Не запрашивать контрольную фразу")
    parser.add_argument(
        "--verify", action="store_true", help="После PATCH проверить каждого пользователя через GET"
    )
    parser.add_argument("--exclude-dismissed", action="store_true", help="Не выгружать уволенных")
    parser.add_argument("--exclude-disabled", action="store_true", help="Не выгружать заблокированных")
    parser.add_argument("--exclude-robots", action="store_true", help="Не выгружать роботов")
    parser.add_argument(
        "--duration",
        type=int,
        default=0,
        help="Для domain-enable: период отсрочки настройки 2FA в секундах",
    )
    parser.add_argument(
        "--logout-users",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Для domain-enable: завершить пользовательские сессии",
    )
    parser.add_argument(
        "--validation-method",
        choices=("default", "phone"),
        default="default",
        help="Для domain-enable: метод проверки второго фактора",
    )
    return parser


def validate_args(args: argparse.Namespace) -> None:
    if not 1 <= args.workers <= 10:
        raise AppError("--workers должен быть в диапазоне 1-10")
    if not 1 <= args.timeout <= 300:
        raise AppError("--timeout должен быть в диапазоне 1-300")
    if not 0 <= args.retries <= 10:
        raise AppError("--retries должен быть в диапазоне 0-10")
    if args.duration < 0:
        raise AppError("--duration не может быть отрицательным")
    if args.action == "export" and args.dry_run:
        raise AppError("--dry-run применяется только к apply или interactive")
    if args.action == "apply" and args.file is None:
        raise AppError("Для apply обязательно укажите --file")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        validate_args(args)
        token, org_id = get_credentials(args.env_file)

        if args.action == "status":
            print(json.dumps(get_domain_2fa(token, org_id, args.timeout, args.retries), ensure_ascii=False, indent=2))
            return 0
        if args.action == "domain-enable":
            return enable_domain_per_user(args, token, org_id)
        if args.action == "export":
            output = args.file or script_dir() / f"users_2fa_{org_id}_{timestamp()}.csv"
            exported, excluded = export_users(args, token, org_id, output)
            print(f"Выгружено пользователей: {exported}; исключено: {excluded}.")
            print(f"CSV: {output}")
            return 0
        if args.action == "apply":
            return apply_file(args, token, org_id, args.file.resolve())

        output = args.file or script_dir() / f"users_2fa_{org_id}_{timestamp()}.csv"
        exported, excluded = export_users(args, token, org_id, output)
        print(f"Выгружено пользователей: {exported}; исключено: {excluded}.")
        print("Удалите из CSV ненужные строки. UID, login, email и заголовки не изменяйте.")
        print(f"CSV: {output}")
        input("После сохранения и закрытия CSV нажмите Enter...")
        return apply_file(args, token, org_id, output.resolve())
    except KeyboardInterrupt:
        eprint("\nОперация прервана пользователем.")
        return 130
    except AppError as exc:
        eprint(f"Ошибка: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

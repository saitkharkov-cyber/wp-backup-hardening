#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import base64
import hashlib
import re
from pathlib import Path
from urllib.parse import urlparse

HEX32_RE = re.compile(r"^[a-f0-9]{32}$", re.I)

STRONG_MARKERS = [
    "HTTP_X_FORWARDED_FOR",
    "HTTP_CF_CONNECTING_IP",
    "REMOTE_ADDR",
    "posts_where_paged",
    "author__not_in",
    "wp_count_posts",
    "wpseo_robots",
    "wpseo_googlebot",
    "wpseo_bingbot",
    "gstatic.com/ipranges",
    "goog.txt",
    "gamblersrules",
]

WEAK_MARKERS = [
    "source",
    "ranges",
    "timestamp",
    "post_author NOT IN",
    "comments_open",
]


def malware_option_key(domain: str) -> str:
    md5_1 = hashlib.md5(domain.encode("utf-8")).hexdigest()
    sha1_1 = hashlib.sha1(md5_1.encode("utf-8")).hexdigest()
    return hashlib.md5(sha1_1.encode("utf-8")).hexdigest()


def extract_domain(value: str):
    try:
        p = urlparse(value.strip())
        return p.hostname.lower() if p.hostname else None
    except Exception:
        return None


def maybe_b64_decode(value: str):
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 80 or len(compact) % 4 != 0:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        return None
    try:
        raw = base64.b64decode(compact, validate=True)
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def marker_hits(text: str):
    low = text.lower()
    strong = [m for m in STRONG_MARKERS if m.lower() in low]
    weak = [m for m in WEAK_MARKERS if m.lower() in low]
    return strong, weak


def sql_unescape(value: str) -> str:
    out = []
    i = 0
    mapping = {
        "0": "\0", "n": "\n", "r": "\r", "t": "\t",
        "b": "\b", "Z": "\x1a", "'": "'", '"': '"', "\\": "\\",
    }
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            out.append(mapping.get(nxt, nxt))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def split_sql_tuple(tuple_text: str):
    fields = []
    buf = []
    in_string = False
    escaped = False

    for ch in tuple_text:
        if in_string:
            if escaped:
                buf.append("\\")
                buf.append(ch)
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == "'":
                in_string = False
            else:
                buf.append(ch)
        else:
            if ch == "'":
                in_string = True
            elif ch == ",":
                fields.append(sql_unescape("".join(buf).strip()))
                buf = []
            else:
                buf.append(ch)

    fields.append(sql_unescape("".join(buf).strip()))
    return fields


def iter_insert_tuples(path: Path):
    current_table = None
    collecting = False
    in_string = False
    escaped = False
    depth = 0
    tuple_buf = []

    insert_re = re.compile(r"^\s*INSERT\s+INTO\s+`([^`]+)`", re.I)

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not collecting:
                m = insert_re.search(line)
                if not m:
                    continue

                current_table = m.group(1)

                if not (
                    current_table.endswith("_options")
                    or current_table.endswith("_postmeta")
                ):
                    continue

                collecting = True
                pos = re.search(r"\bVALUES\b", line, re.I)
                chunk = line[pos.end():] if pos else ""
            else:
                chunk = line

            i = 0
            while i < len(chunk):
                ch = chunk[i]

                if in_string:
                    if escaped:
                        tuple_buf.append(ch)
                        escaped = False
                    elif ch == "\\":
                        tuple_buf.append(ch)
                        escaped = True
                    elif ch == "'":
                        tuple_buf.append(ch)
                        in_string = False
                    else:
                        tuple_buf.append(ch)

                else:
                    if ch == "'":
                        if depth > 0:
                            tuple_buf.append(ch)
                        in_string = True

                    elif ch == "(":
                        if depth == 0:
                            tuple_buf = []
                        else:
                            tuple_buf.append(ch)
                        depth += 1

                    elif ch == ")":
                        depth -= 1
                        if depth == 0:
                            raw_tuple = "".join(tuple_buf)
                            yield current_table, split_sql_tuple(raw_tuple)
                            tuple_buf = []
                        elif depth > 0:
                            tuple_buf.append(ch)

                    elif ch == ";" and depth == 0:
                        collecting = False
                        current_table = None
                        in_string = False
                        escaped = False
                        tuple_buf = []
                        break

                    else:
                        if depth > 0:
                            tuple_buf.append(ch)

                i += 1


def fmt_item(item):
    extra = f" | post_id={item['post_id']}" if "post_id" in item else ""
    return (
        f"{item['table']} | id={item['id']}{extra} | "
        f"key={item['key']} | len={item['value_len']} | {item['reason']}"
    )


def scan_dump(path: Path):
    option_rows = []
    postmeta_rows = []
    domains = set()
    option_tables = set()
    postmeta_tables = set()

    for table, fields in iter_insert_tuples(path):
        if table.endswith("_options") and len(fields) >= 4:
            option_tables.add(table)
            row = {
                "table": table,
                "id": fields[0],
                "key": fields[1],
                "value": fields[2],
                "autoload": fields[3],
            }
            option_rows.append(row)

            if row["key"] in ("siteurl", "home"):
                d = extract_domain(row["value"])
                if d:
                    domains.add(d)

        elif table.endswith("_postmeta") and len(fields) >= 4:
            postmeta_tables.add(table)
            postmeta_rows.append({
                "table": table,
                "id": fields[0],
                "post_id": fields[1],
                "key": fields[2],
                "value": fields[3],
            })

    expected_keys = {malware_option_key(d): d for d in domains}
    confirmed = []
    review = []

    def inspect(row):
        key = row["key"]
        value = row["value"]
        value_len = len(value)

        decoded = maybe_b64_decode(value)
        raw_strong, _ = marker_hits(value)
        dec_strong, dec_weak = marker_hits(decoded or "")

        if key in expected_keys:
            parts = [
                f"ключ совпадает с md5(sha1(md5('{expected_keys[key]}')))"
            ]
            if decoded:
                parts.append("Base64 payload декодируется")
            if dec_strong:
                parts.append("маркеры: " + ", ".join(dec_strong[:6]))

            confirmed.append({
                **row,
                "value_len": value_len,
                "reason": "; ".join(parts),
            })
            return

        if decoded and len(dec_strong) >= 2:
            confirmed.append({
                **row,
                "value_len": value_len,
                "reason": "Base64 payload содержит malware-маркеры: "
                          + ", ".join(dec_strong[:8]),
            })
            return

        if len(raw_strong) >= 2:
            confirmed.append({
                **row,
                "value_len": value_len,
                "reason": "значение содержит malware-маркеры: "
                          + ", ".join(raw_strong[:8]),
            })
            return

        if HEX32_RE.fullmatch(key):
            details = ["32-символьный hex-ключ"]

            if decoded:
                details.append("Base64 декодируется")
                if re.match(r"^[aObisdN]:", decoded[:20]):
                    details.append("похоже на PHP serialized")
                if dec_weak:
                    details.append("слабые маркеры: " + ", ".join(dec_weak[:5]))

            review.append({
                **row,
                "value_len": value_len,
                "reason": "; ".join(details),
            })
            return

        if decoded and value_len >= 200 and re.match(r"^[aObisdN]:", decoded[:20]):
            review.append({
                **row,
                "value_len": value_len,
                "reason": "длинный Base64 payload → PHP serialized",
            })

    for row in option_rows:
        inspect(row)

    for row in postmeta_rows:
        inspect(row)

    return {
        "option_tables": sorted(option_tables),
        "postmeta_tables": sorted(postmeta_tables),
        "option_count": len(option_rows),
        "postmeta_count": len(postmeta_rows),
        "domains": sorted(domains),
        "expected_keys": expected_keys,
        "confirmed": confirmed,
        "review": review,
    }


def write_report(result, report_path: Path, dump_path: Path):
    with report_path.open("w", encoding="utf-8") as f:
        f.write("WORDPRESS DB PRECHECK — V2\n")
        f.write(f"Dump: {dump_path}\n")
        f.write(
            "Options table(s): "
            + (", ".join(result["option_tables"]) or "не определены")
            + "\n"
        )
        f.write(
            "Postmeta table(s): "
            + (", ".join(result["postmeta_tables"]) or "не определены")
            + "\n"
        )
        f.write(f"Options rows parsed: {result['option_count']}\n")
        f.write(f"Postmeta rows parsed: {result['postmeta_count']}\n")

        if result["domains"]:
            f.write("Domains: " + ", ".join(result["domains"]) + "\n")

        f.write("\n" + "=" * 78 + "\n")
        f.write("[CONFIRMED-LIKE] Сильные следы известного cloaking-family\n")
        f.write("=" * 78 + "\n")

        if result["confirmed"]:
            for item in result["confirmed"]:
                f.write(fmt_item(item) + "\n")
        else:
            f.write("Ничего не найдено.\n")

        f.write("\n" + "=" * 78 + "\n")
        f.write("[REVIEW] Подозрительные option/meta записи\n")
        f.write("=" * 78 + "\n")

        if result["review"]:
            for item in result["review"]:
                f.write(fmt_item(item) + "\n")
        else:
            f.write("Ничего не найдено.\n")

        f.write("\n" + "=" * 78 + "\n")
        f.write("[INFO] Вычисленные malware-key для доменов\n")
        f.write("=" * 78 + "\n")

        if result["expected_keys"]:
            for key, domain in result["expected_keys"].items():
                f.write(f"domain: {domain} → expected malware key: {key}\n")
        else:
            f.write("Домены из siteurl/home не определены.\n")

        f.write("\n" + "=" * 78 + "\n")
        f.write("КРАТКАЯ ИНТЕРПРЕТАЦИЯ\n")
        f.write("=" * 78 + "\n")

        if result["confirmed"]:
            f.write(
                f"Найдено {len(result['confirmed'])} сильных DB-следов "
                f"известного malware/cloaking-family.\n"
            )
        elif result["review"]:
            f.write(
                f"Сильных DB-следов не найдено, но есть "
                f"{len(result['review'])} записей для ручной проверки.\n"
            )
        else:
            f.write(
                "По известным сигнатурам wp_options/postmeta "
                "подозрительных записей не найдено.\n"
            )

        f.write("\nСкрипт только читает SQL-дамп и ничего не изменяет.\n")


def main():
    ap = argparse.ArgumentParser(
        description="WordPress DB malware/cloaking precheck по SQL-дампу."
    )
    ap.add_argument("sql_dump", help="Путь к SQL-дампу")
    ap.add_argument(
        "-o", "--output",
        help="Файл отчёта. По умолчанию wp_db_precheck_report_v2.txt рядом с дампом."
    )
    args = ap.parse_args()

    dump = Path(args.sql_dump).resolve()

    if not dump.is_file():
        raise SystemExit(f"Файл не найден: {dump}")

    report = (
        Path(args.output).resolve()
        if args.output
        else dump.parent / "wp_db_precheck_report_v2.txt"
    )

    result = scan_dump(dump)
    write_report(result, report, dump)

    print("Готово.")
    print("Отчёт:", report)
    print("Options rows:", result["option_count"])
    print("Postmeta rows:", result["postmeta_count"])
    print("CONFIRMED-LIKE:", len(result["confirmed"]))
    print("REVIEW:", len(result["review"]))


if __name__ == "__main__":
    main()

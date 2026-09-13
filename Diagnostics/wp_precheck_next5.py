#!/usr/bin/env python3
# wp_precheck_next5.py
# Быстрый предварительный аудит скачанного WordPress-сайта.
# Python 3.9+
#
# Использование:
#   python wp_precheck.py "D:\sites\example"
#
# Результат:
#   wp_precheck_report.txt в текущей папке.
#
# Скрипт ничего не изменяет и не удаляет.

import os
import re
import sys
import time
from pathlib import Path
from datetime import datetime

RECENT_DAYS = 30
MAX_SCAN_FILE = 5 * 1024 * 1024  # 5 MB

EXEC_EXTS = {
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8",
    ".phar", ".cgi", ".pl", ".py", ".sh", ".bash"
}

PHP_EXTS = {
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8", ".inc"
}

SUSPICIOUS_EXTS = {
    ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8",
    ".phar", ".cgi", ".pl"
}

ROOT_ALLOWED = {
    "index.php", "wp-activate.php", "wp-blog-header.php", "wp-comments-post.php",
    "wp-config-sample.php", "wp-config.php", "wp-cron.php", "wp-links-opml.php",
    "wp-load.php", "wp-login.php", "wp-mail.php", "wp-settings.php",
    "wp-signup.php", "wp-trackback.php", "xmlrpc.php",
    ".htaccess", "robots.txt", "license.txt", "readme.html",
    "favicon.ico"
}

SKIP_DIRS = {
    ".git", ".svn", "node_modules"
}

DOUBLE_EXT_RE = re.compile(
    r"\.(jpg|jpeg|png|gif|webp|svg|ico|txt|pdf|zip|docx?|xlsx?|mp3|mp4)\."
    r"(php\d*|phtml|phar|cgi|pl)$",
    re.I
)

# Сильные сигнатуры. Само наличие eval/base64_decode/system и т.п.
# НЕ считается заражением: важны сочетания и контекст.
PHP_PATTERNS = [
    ("eval(base64_decode(...))",
     re.compile(rb"eval\s*\(\s*base64_decode\s*\(", re.I)),

    ("eval(gzinflate(...))",
     re.compile(rb"eval\s*\(\s*gzinflate\s*\(", re.I)),

    ("assert(base64_decode(...))",
     re.compile(rb"assert\s*\(\s*base64_decode\s*\(", re.I)),

    ("base64_decode + gzinflate",
     re.compile(
         rb"(base64_decode\s*\([^;]{0,800}gzinflate|"
         rb"gzinflate\s*\([^;]{0,800}base64_decode)",
         re.I | re.S
     )),

    ("preg_replace /e",
     re.compile(rb"preg_replace\s*\(\s*['\"][^'\"]*/e[^'\"]*['\"]", re.I)),

    ("команда ОС получает данные из HTTP-запроса",
     re.compile(
         rb"(system|exec|shell_exec|passthru|popen|proc_open)\s*"
         rb"\([^;]{0,400}\$_(GET|POST|REQUEST|COOKIE)",
         re.I | re.S
     )),

    ("динамический вызов функции из HTTP-запроса",
     re.compile(
         rb"(\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\()|"
         rb"(\$\w+\s*=\s*\$_(GET|POST|REQUEST|COOKIE)[^;]{0,200};"
         rb"[^;]{0,300}\$\w+\s*\()",
         re.I | re.S
     )),

    ("create_function + декодирование",
     re.compile(
         rb"create_function\s*\([^;]{0,700}"
         rb"(base64_decode|gzinflate|str_rot13)",
         re.I | re.S
     )),

    ("include/require из HTTP-параметра",
     re.compile(
         rb"(include|include_once|require|require_once)\s*"
         rb"\(?\s*\$_(GET|POST|REQUEST|COOKIE)",
         re.I
     )),

    # Прямое выполнение значения HTTP-заголовка / $_SERVER.
    ("eval() получает значение из $_SERVER",
     re.compile(
         rb"eval\s*\(\s*\$_SERVER\s*\[[^\]]+\]\s*\)",
         re.I | re.S
     )),

    # eval($x), где $x раньше присвоен из $_SERVER[...] напрямую.
    ("eval() выполняет переменную из $_SERVER",
     re.compile(
         rb"\$(\w+)\s*=\s*\$_SERVER\s*\[[^\]]+\]\s*;"
         rb".{0,1200}?eval\s*\(\s*\$\1\s*\)",
         re.I | re.S
     )),

    # Ловит схему:
    # $a = $_SERVER;
    # $b = 'HTTP_XXXX';
    # eval($a[$b]);
    ("выполнение кода из HTTP-заголовка через eval()",
     re.compile(
         rb"\$(\w+)\s*=\s*\$_SERVER\s*;"
         rb".{0,800}?\$(\w+)\s*=\s*['\"]HTTP_[A-Z0-9_\-]{3,}['\"]\s*;"
         rb".{0,1200}?eval\s*\(\s*\$\1\s*\[\s*\$\2\s*\]\s*\)",
         re.I | re.S
     )),

    # Нестандартный HTTP_* ключ и опасная функция поблизости.
    ("нестандартный HTTP_* заголовок рядом с выполнением кода",
     re.compile(
         rb"HTTP_[A-Z0-9_\-]{4,}.{0,1200}?"
         rb"(eval|assert|system|exec|shell_exec|passthru)\s*\(",
         re.I | re.S
     )),

    # Общий eval($variable) + происхождение переменной из внешних супер-глобалов
    # через промежуточное присваивание. Ограничиваем окно, чтобы не шуметь.
    ("eval() выполняет данные внешнего запроса",
     re.compile(
         rb"\$(\w+)\s*=\s*\$_(SERVER|GET|POST|REQUEST|COOKIE)"
         rb"(?:\s*\[[^\]]+\])?\s*;"
         rb".{0,1200}?eval\s*\(\s*\$\1(?:\s*\[[^\]]+\])?\s*\)",
         re.I | re.S
     )),
]

# Композитные признаки SEO-spam / cloaking implant.
# Они проверяются отдельно, потому что по одной функции вроде get_option()
# или wp_remote_get() нельзя делать вывод о заражении.
SEO_CLOAK_PATTERNS = [
    (
        "скрытая конфигурация: get_option + base64_decode + unserialize",
        [
            re.compile(rb"get_option\s*\(", re.I),
            re.compile(rb"base64_decode\s*\(", re.I),
            re.compile(rb"unserialize\s*\(", re.I),
        ],
    ),
    (
        "скрытая конфигурация на основе HTTP_HOST",
        [
            re.compile(rb"HTTP_HOST", re.I),
            re.compile(rb"\bmd5\s*\(", re.I),
            re.compile(rb"\bsha1\s*\(", re.I),
            re.compile(rb"get_option\s*\(", re.I),
        ],
    ),
    (
        "удалённая конфигурация/список через wp_remote_get",
        [
            re.compile(rb"wp_remote_get\s*\(", re.I),
            re.compile(rb"wp_remote_retrieve_body\s*\(", re.I),
            re.compile(rb"update_option\s*\(", re.I),
        ],
    ),
    (
        "скрытие/фильтрация контента WordPress",
        [
            re.compile(rb"pre_get_posts|posts_where_paged|wp_count_posts", re.I),
            re.compile(rb"author__not_in|post_author", re.I),
        ],
    ),
    (
        "вывод скрытого контента из конфигурации/meta",
        [
            re.compile(rb"get_post_meta\s*\(|get_option\s*\(", re.I),
            re.compile(rb"echo\s+\$[A-Za-z_][A-Za-z0-9_]*\s*\[", re.I),
        ],
    ),
]


SEO_CLOAK_STRONG = [
    re.compile(rb"wp_remote_get\s*\(", re.I),
    re.compile(rb"author__not_in|posts_where_paged|wp_count_posts", re.I),
    re.compile(rb"HTTP_HOST", re.I),
    re.compile(rb"base64_decode\s*\(", re.I),
    re.compile(rb"unserialize\s*\(", re.I),
]




def fmt_time(ts):
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "?"


def rel(path, root):
    try:
        return str(path.relative_to(root))
    except Exception:
        return str(path)


def is_under(path, dirname):
    return dirname.lower() in [p.lower() for p in path.parts]




def is_wp_core_path(path, root):
    """
    Считаем ядром только wp-admin/* и wp-includes/*.
    Корневые wp-*.php остаются отдельно: среди них тоже возможна подмена.
    """
    try:
        relp = path.relative_to(root)
        if not relp.parts:
            return False
        return relp.parts[0].lower() in {"wp-admin", "wp-includes"}
    except Exception:
        return False


def looks_like_backupbuddy_file(path):
    """
    Файлы BackupBuddy / ImportBuddy внутри uploads.

    Они могут быть PHP и при этом быть штатными служебными файлами плагина.
    Поэтому сам факт нахождения такого PHP в uploads не делает его backdoor.

    Всё, кроме маленьких index.php-заглушек, показываем как REVIEW:
    restore/import/settings-файлы всё равно желательно удалить или проверить,
    если они больше не нужны.
    """
    parts = [x.lower() for x in path.parts]
    name = path.name.lower()

    backupbuddy_dirs = {
        "backupbuddy_temp",
        "backupbuddy_backups",
        "pb_backupbuddy",
    }

    if any(part in backupbuddy_dirs for part in parts):
        return True

    # Дополнительная страховка для характерных имён BackupBuddy.
    if (
        name == "importbuddy.php"
        or name == "backupbuddy_dat.php"
        or name.startswith("settings_backup-")
    ):
        return True

    return False


def looks_like_tiny_backupbuddy_index(path, size, data=None):
    """
    Маленькие index.php-заглушки BackupBuddy считаем INFO,
    если они действительно крошечные и не содержат опасных конструкций.
    """
    if path.name.lower() != "index.php":
        return False

    if not looks_like_backupbuddy_file(path):
        return False

    if size > 100:
        return False

    dangerous = (
        b"eval(",
        b"assert(",
        b"base64_decode(",
        b"gzinflate(",
        b"shell_exec(",
        b"system(",
        b"exec(",
        b"passthru(",
        b"preg_replace",
        b"$_GET",
        b"$_POST",
        b"$_REQUEST",
        b"$_COOKIE",
        b"$_SERVER",
    )

    try:
        if data is None:
            data = path.read_bytes()
        low = data.lower()
    except Exception:
        return False

    return not any(token.lower() in low for token in dangerous)



def looks_like_placeholder_php(path):
    """
    Мелкие index.php-заглушки вида:
      <?php
      // Silence is golden.
    не считаем критическим признаком.
    """
    try:
        if path.stat().st_size > 300:
            return False
        data = path.read_bytes().lower()
        harmless_markers = [
            b"silence is golden",
            b"silence is gold",
            b"nothing to see",
        ]
        if any(x in data for x in harmless_markers):
            return True
        stripped = re.sub(rb"\s+", b"", data)
        return stripped in {
            b"<?php",
            b"<?php?>",
            b"<?php//silenceisgolden.",
        }
    except Exception:
        return False


def main():
    if len(sys.argv) < 2:
        print(r'Использование: python wp_precheck.py "D:\path\to\site"')
        sys.exit(1)

    root = Path(sys.argv[1]).resolve()
    if not root.is_dir():
        print("Папка не найдена:", root)
        sys.exit(1)

    cutoff = time.time() - RECENT_DAYS * 86400

    findings = {
        "uploads_exec_high": [],
        "uploads_exec_info": [],
        "uploads_backupbuddy": [],
        "double_ext": [],
        "suspicious_ext": [],
        "recent_php": [],
        "root_unusual": [],
        "content_hits": [],
        "seo_cloak_hits": [],
        "confirmed_like": [],
        "review_hits": [],
        "special_files": [],
    }

    total_files = 0
    php_files = 0
    scanned_content = 0
    errors = []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
        base = Path(dirpath)

        for name in filenames:
            total_files += 1
            p = base / name
            low = name.lower()
            ext = p.suffix.lower()

            try:
                st = p.stat()
            except Exception as e:
                errors.append(f"{rel(p, root)} :: {e}")
                continue

            r = rel(p, root)

            # Файлы, которые полезно быстро просмотреть отдельно.
            if low in {".htaccess", "wp-config.php", "robots.txt"}:
                findings["special_files"].append((r, st.st_size, st.st_mtime))

            # Исполняемые файлы в uploads.
            if is_under(p, "uploads") and ext in EXEC_EXTS:
                item = (r, st.st_size, st.st_mtime)

                # Универсальные безобидные index.php-заглушки.
                if ext in PHP_EXTS and looks_like_placeholder_php(p):
                    findings["uploads_exec_info"].append(item)

                # BackupBuddy часто кладёт в uploads крошечные index.php
                # размером 13 байт. Если там нет опасных функций — это INFO.
                elif ext in PHP_EXTS and looks_like_tiny_backupbuddy_index(p, st.st_size):
                    findings["uploads_exec_info"].append(item)

                # Остальные характерные файлы BackupBuddy/ImportBuddy —
                # REVIEW, а не CONFIRMED-LIKE.
                elif looks_like_backupbuddy_file(p):
                    findings["uploads_backupbuddy"].append(item)

                else:
                    findings["uploads_exec_high"].append(item)

            # Двойное расширение image.jpg.php.
            # Проверяем только пользовательские каталоги, чтобы не ловить штатные
            # файлы ядра вроде wp-includes/ID3/module.audio.mp3.php.
            if DOUBLE_EXT_RE.search(low) and (
                is_under(p, "uploads") or
                is_under(p, "cache") or
                is_under(p, "tmp") or
                is_under(p, "temp")
            ):
                findings["double_ext"].append((r, st.st_size, st.st_mtime))

            # Нехарактерные серверные расширения.
            if ext in SUSPICIOUS_EXTS:
                findings["suspicious_ext"].append((r, st.st_size, st.st_mtime))

            # Необычные файлы в корне.
            if p.parent == root and low not in ROOT_ALLOWED:
                findings["root_unusual"].append((r, st.st_size, st.st_mtime))

            # Свежие PHP.
            if ext in PHP_EXTS:
                php_files += 1
                if st.st_mtime >= cutoff:
                    findings["recent_php"].append((r, st.st_size, st.st_mtime))

            # Контент-скан только PHP-подобных файлов.
            # JS/HTML/TXT намеренно исключены: там слишком много ложных срабатываний.
            if ext in PHP_EXTS and st.st_size <= MAX_SCAN_FILE:
                try:
                    data = p.read_bytes()
                    scanned_content += 1

                    for label, rx in PHP_PATTERNS:
                        if rx.search(data):
                            findings["content_hits"].append(
                                (r, label, st.st_size, st.st_mtime)
                            )

                    seo_labels = []
                    for label, regexes in SEO_CLOAK_PATTERNS:
                        if all(rx.search(data) for rx in regexes):
                            seo_labels.append(label)

                    core_path = is_wp_core_path(p, root)
                    strong_count = sum(1 for rx in SEO_CLOAK_STRONG if rx.search(data))

                    # Для файлов ядра WordPress порог выше:
                    # слабые сочетания get_option/base64/unserialize сами по себе шумные.
                    if core_path:
                        if len(seo_labels) >= 3 and strong_count >= 3:
                            findings["seo_cloak_hits"].append(
                                (r, "; ".join(seo_labels), st.st_size, st.st_mtime)
                            )
                    else:
                        if len(seo_labels) >= 2:
                            findings["seo_cloak_hits"].append(
                                (r, "; ".join(seo_labels), st.st_size, st.st_mtime)
                            )

                except Exception as e:
                    errors.append(f"{r} :: {e}")

    # Убираем точные дубли.
    findings["content_hits"] = list(dict.fromkeys(findings["content_hits"]))
    findings["seo_cloak_hits"] = list(dict.fromkeys(findings["seo_cloak_hits"]))

    # Группируем несколько сильных сигнатур одного файла в одну строку.
    grouped = {}
    for r, label, size, mtime in findings["content_hits"]:
        key = (r, size, mtime)
        grouped.setdefault(key, []).append(label)

    grouped_hits = []
    for (r, size, mtime), labels in grouped.items():
        labels = list(dict.fromkeys(labels))
        grouped_hits.append((r, " | ".join(labels), size, mtime))
    findings["content_hits"] = grouped_hits

    # Классификация по уровню уверенности.
    for item in findings["content_hits"]:
        r, labels, size, mtime = item
        low_labels = labels.lower()
        if (
            "выполнение кода из http-заголовка через eval()" in low_labels
            or "eval() получает значение из $_server" in low_labels
            or "eval() выполняет переменную из $_server" in low_labels
            or "eval() выполняет данные внешнего запроса" in low_labels
        ):
            findings["confirmed_like"].append(
                (r, labels, size, mtime)
            )
        else:
            findings["review_hits"].append(
                (r, labels, size, mtime)
            )

    for item in findings["seo_cloak_hits"]:
        findings["confirmed_like"].append(item)

    out = Path.cwd() / "wp_precheck_report.txt"

    def section(f, title, rows, formatter):
        f.write("\n" + "=" * 78 + "\n")
        f.write(title + "\n")
        f.write("=" * 78 + "\n")
        if not rows:
            f.write("Ничего не найдено.\n")
            return
        for row in rows:
            f.write(formatter(row) + "\n")

    high_count = (
        len(findings["uploads_exec_high"])
        + len(findings["double_ext"])
        + len(findings["confirmed_like"])
    )

    review_count = (
        len(findings["review_hits"])
        + len(findings["uploads_backupbuddy"])
        + len(findings["suspicious_ext"])
    )

    medium_count = len(findings["suspicious_ext"])

    with out.open("w", encoding="utf-8") as f:
        f.write("WORDPRESS PRECHECK — NEXT 5\n")
        f.write(f"Путь: {root}\n")
        f.write(f"Дата проверки: {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write(f"Файлов всего: {total_files}\n")
        f.write(f"PHP/INC-файлов: {php_files}\n")
        f.write(f"PHP/INC-файлов проверено по содержимому: {scanned_content}\n")
        f.write(f"Порог 'свежих' файлов: {RECENT_DAYS} дней\n")

        section(
            f,
            "[CONFIRMED-LIKE] Исполняемые файлы внутри uploads",
            findings["uploads_exec_high"],
            lambda x: f"{x[0]} | {x[1]} bytes | {fmt_time(x[2])}"
        )

        section(
            f,
            "[INFO] Безобидные PHP-заглушки внутри uploads",
            findings["uploads_exec_info"],
            lambda x: f"{x[0]} | {x[1]} bytes | {fmt_time(x[2])}"
        )

        section(
            f,
            "[REVIEW] Служебные/восстановительные файлы BackupBuddy",
            findings["uploads_backupbuddy"],
            lambda x: f"{x[0]} | {x[1]} bytes | {fmt_time(x[2])}"
        )

        section(
            f,
            "[CONFIRMED-LIKE] Двойные расширения (например image.jpg.php)",
            findings["double_ext"],
            lambda x: f"{x[0]} | {x[1]} bytes | {fmt_time(x[2])}"
        )

        section(
            f,
            "[CONFIRMED-LIKE] Очень сильные признаки backdoor / cloaking",
            findings["confirmed_like"],
            lambda x: f"{x[0]} | {x[1]} | {x[2]} bytes | {fmt_time(x[3])}"
        )

        section(
            f,
            "[REVIEW] Подозрительные конструкции, требующие ручной проверки",
            findings["review_hits"],
            lambda x: f"{x[0]} | {x[1]} | {x[2]} bytes | {fmt_time(x[3])}"
        )

        section(
            f,
            "[REVIEW] Нехарактерные серверные расширения",
            findings["suspicious_ext"],
            lambda x: f"{x[0]} | {x[1]} bytes | {fmt_time(x[2])}"
        )

        section(
            f,
            f"[INFO] PHP/INC-файлы, изменённые за последние {RECENT_DAYS} дней",
            sorted(findings["recent_php"], key=lambda x: x[2], reverse=True),
            lambda x: f"{fmt_time(x[2])} | {x[0]} | {x[1]} bytes"
        )

        section(
            f,
            "[INFO] Необычные файлы в корне",
            findings["root_unusual"],
            lambda x: f"{x[0]} | {x[1]} bytes | {fmt_time(x[2])}"
        )

        section(
            f,
            "[INFO] Файлы для отдельного ручного просмотра",
            findings["special_files"],
            lambda x: f"{x[0]} | {x[1]} bytes | {fmt_time(x[2])}"
        )

        if errors:
            section(
                f,
                "[INFO] Ошибки чтения",
                errors,
                lambda x: x
            )

        f.write("\n" + "=" * 78 + "\n")
        f.write("КРАТКАЯ ИНТЕРПРЕТАЦИЯ\n")
        f.write("=" * 78 + "\n")

        if high_count == 0 and review_count == 0:
            f.write("Уровень предварительного риска: НИЗКИЙ\n")
            f.write("Сильных признаков заражения по быстрым файловым эвристикам не найдено.\n")
        elif high_count == 0:
            f.write("Уровень предварительного риска: НИЗКИЙ / ТРЕБУЕТ ПРОСМОТРА\n")
            f.write(
                f"Сильных признаков нет, но есть {review_count} элементов для ручной проверки.\n"
            )
        elif high_count <= 2:
            f.write("Уровень предварительного риска: ВЫСОКИЙ\n")
            f.write(
                f"Найдено {high_count} очень сильных признаков возможного заражения. "
                f"Рекомендуется полноценный аудит.\n"
            )
        else:
            f.write("Уровень предварительного риска: ПОВЫШЕННЫЙ / ВЕРОЯТНО ЗАРАЖЁН\n")
            f.write(
                f"Найдено {high_count} очень сильных признаков backdoor/cloaking. "
                f"Полноценный аудит настоятельно рекомендуется.\n"
            )

        f.write(
            "\nВажно:\n"
            "- это предварительная оценка, а не антивирусное заключение;\n"
            "- наличие сигнатуры ещё не доказывает заражение;\n"
            "- отсутствие срабатываний не гарантирует отсутствие скрытого вредоносного кода;\n"
            "- скрипт ничего не изменяет и не удаляет.\n"
        )

    print("Готово.")
    print("Отчёт:", out)
    print()
    print("Ключевые результаты:")
    print("  Опасные исполняемые файлы в uploads:", len(findings["uploads_exec_high"]))
    print("  Безобидные PHP-заглушки в uploads:", len(findings["uploads_exec_info"]))
    print("  BackupBuddy/ImportBuddy для ручного просмотра:", len(findings["uploads_backupbuddy"]))
    print("  Двойные расширения:", len(findings["double_ext"]))
    print("  CONFIRMED-LIKE:", len(findings["confirmed_like"]))
    print("  REVIEW:", len(findings["review_hits"]))
    print("  SEO-cloaking / hidden-content implants:", len(findings["seo_cloak_hits"]))
    print("  Нехарактерные серверные расширения:", len(findings["suspicious_ext"]))
    print("  Свежие PHP/INC:", len(findings["recent_php"]))
    print("  Необычные файлы в корне:", len(findings["root_unusual"]))


if __name__ == "__main__":
    main()

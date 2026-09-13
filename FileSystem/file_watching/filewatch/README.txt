FILEWATCH v2.4

Ключ:
UkjfIzJ_wdqMrxTqOhrgfkdF82pNOwNwfXsBzK8Q3Pw

Главное изменение v2:
- штатная PAUSE/RESUME схема;
- во время паузы cron endpoint продолжает отвечать 200 OK;
- scan и mail не выполняются;
- resume запрещён, пока после паузы не создан новый baseline;
- добавлен status endpoint.

Установка:
1. Положить папку filewatch в корень WordPress.
2. В filewatch_config.php заменить:
   YOUR_EMAIL@example.com
   на свой e-mail.

URL:

Статус:
https://SITE/filewatch/filewatch_status.php?key=UkjfIzJ_wdqMrxTqOhrgfkdF82pNOwNwfXsBzK8Q3Pw

Создать / пересоздать baseline:
https://SITE/filewatch/filewatch_init.php?key=UkjfIzJ_wdqMrxTqOhrgfkdF82pNOwNwfXsBzK8Q3Pw

Поставить на паузу:
https://SITE/filewatch/filewatch_pause.php?key=UkjfIzJ_wdqMrxTqOhrgfkdF82pNOwNwfXsBzK8Q3Pw

Возобновить:
https://SITE/filewatch/filewatch_resume.php?key=UkjfIzJ_wdqMrxTqOhrgfkdF82pNOwNwfXsBzK8Q3Pw

Быстрая проверка:
https://SITE/filewatch/filewatch_check.php?key=UkjfIzJ_wdqMrxTqOhrgfkdF82pNOwNwfXsBzK8Q3Pw

Полный SHA-256 проход порциями:
https://SITE/filewatch/filewatch_check.php?mode=full&key=UkjfIzJ_wdqMrxTqOhrgfkdF82pNOwNwfXsBzK8Q3Pw

Рабочий цикл при плановых изменениях:
1. PAUSE
2. Внести изменения
3. Проверить сайт
4. Пересоздать baseline
5. RESUME

Важно:
- baseline никогда не обновляется автоматически;
- resume после pause блокируется, если baseline не пересоздан;
- обычные файлы uploads не мониторятся, но структура директорий мониторится;
- PHP/исполняемые файлы внутри uploads мониторятся;
- baseline/state хранятся выше web-root.


v2.1: совместимость с PHP 7.4 — убрана зависимость от str_starts_with().


v2.2:
- папка filewatch больше НЕ исключается из контроля: монитор следит и за собственными PHP-файлами;
- QUICK возвращает подробный diff прямо в JSON;
- добавлены Cache-Control: no-store заголовки;
- QUICK и FULL используют отдельные сигнатуры подавления повторных уведомлений;
- добавлен filewatch_mail_test.php для отдельной проверки почты.

Проверка почты:
https://SITE/filewatch/filewatch_mail_test.php?key=KEY

ВАЖНО:
mail_sent=true означает только, что PHP mail() принял письмо для локальной отправки.
Это не гарантирует доставку в Inbox: письмо может быть задержано, попасть в Spam
или быть отклонено почтовым сервером из-за SPF/DKIM/DMARC/репутации отправителя.

После установки v2.2 нужно пересоздать baseline, потому что теперь сама папка filewatch
входит в контролируемый слепок.


v2.3:
- уведомления через Gmail SMTP;
- STARTTLS, smtp.gmail.com:587;
- AUTH LOGIN;
- отдельный SMTP test endpoint;
- PHP mail() оставлен только как резервный driver.

Настройка filewatch_config.php:

const FILEWATCH_ALERT_EMAIL = 'sait.kharkov@gmail.com';

const FILEWATCH_MAIL_DRIVER = 'smtp';
const FILEWATCH_SMTP_HOST = 'smtp.gmail.com';
const FILEWATCH_SMTP_PORT = 587;
const FILEWATCH_SMTP_ENCRYPTION = 'tls';
const FILEWATCH_SMTP_USERNAME = 'sait.kharkov@gmail.com';
const FILEWATCH_SMTP_PASSWORD = '16-значный пароль приложения Google';
const FILEWATCH_SMTP_FROM_EMAIL = 'sait.kharkov@gmail.com';
const FILEWATCH_SMTP_FROM_NAME = 'FileWatch';

ПРОБЕЛЫ В ПАРОЛЕ ПРИЛОЖЕНИЯ:
Google может визуально показывать пароль группами. В конфиг обычно удобнее вставить его без пробелов.

Проверка:
https://SITE/filewatch/filewatch_mail_test.php?key=KEY

После замены v2.2 -> v2.3 пересоздать baseline, потому что файлы FileWatch изменились.


v2.4:
- уведомления можно отправлять на несколько адресов;
- SMTP делает отдельный RCPT TO для каждого получателя;
- дубликаты e-mail автоматически убираются;
- старый FILEWATCH_ALERT_EMAIL поддерживается для обратной совместимости.

Настройка:

const FILEWATCH_ALERT_EMAILS = [
    'sait.kharkov@gmail.com',
    'second@example.com',
    'third@example.com',
];

SMTP-логин/пароль остаются одни: это адрес-отправитель.
Получателей может быть несколько.

После замены v2.3 -> v2.4:
1. PAUSE
2. заменить файлы FileWatch
3. настроить FILEWATCH_ALERT_EMAILS
4. проверить filewatch_mail_test.php
5. пересоздать baseline
6. RESUME
7. HARDEN

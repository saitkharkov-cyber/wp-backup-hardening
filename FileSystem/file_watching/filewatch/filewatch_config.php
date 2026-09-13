<?php
declare(strict_types=1);

const FILEWATCH_KEY = 'UkjfIzJ_wdqMrxTqOhrgfkdF82pNOwNwfXsBzK8Q3Pw';
const FILEWATCH_ALERT_EMAILS = [
    'sait.kharkov@gmail.com',
    // 'second@example.com',
];


const FILEWATCH_MAIL_DRIVER = 'smtp'; // smtp | mail

const FILEWATCH_SMTP_HOST = 'smtp.gmail.com';
const FILEWATCH_SMTP_PORT = 587;
const FILEWATCH_SMTP_ENCRYPTION = 'tls'; // tls for STARTTLS
const FILEWATCH_SMTP_USERNAME = 'sait.kharkov@gmail.com';
const FILEWATCH_SMTP_PASSWORD = 'gxcz pmcf pjka cbxs'; 
const FILEWATCH_SMTP_FROM_EMAIL = 'sait.kharkov@gmail.com';
const FILEWATCH_SMTP_FROM_NAME = 'FileWatch';
const FILEWATCH_SMTP_TIMEOUT = 15;


const FILEWATCH_TIME_BUDGET = 20.0;
const FILEWATCH_FULL_MAX_FILES_PER_RUN = 20000;
const FILEWATCH_MAX_REPORT_LINES = 250;

const FILEWATCH_EXCLUDE_DIRS = [];

const FILEWATCH_UPLOADS_REL = 'wp-content/uploads';

const FILEWATCH_DANGEROUS_UPLOAD_EXT = [
    'php','php3','php4','php5','php7','php8','phtml','phar',
    'inc','cgi','pl','py','sh','bash','exe','dll','so'
];

function filewatch_site_root(): string {
    return realpath(dirname(__DIR__)) ?: dirname(__DIR__);
}

function filewatch_data_dir(): string {
    $root = filewatch_site_root();
    $tag = substr(hash('sha256', $root), 0, 12);
    return dirname($root) . '/.filewatch-data-' . $tag;
}

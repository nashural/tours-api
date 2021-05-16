<?php
return [
    'settings' => [
        'displayErrorDetails' => true, // set to false in production
        'addContentLengthHeader' => false, // Allow the web server to send the content-length header

        'db' => [
            'driver' => 'mysql',
            'host' => getenv('DB_HOST'),
            'database' => getenv('DB_NAME'),
            'username' => getenv('DB_USER'),
            'password' => getenv('DB_PASS'),
            'charset'   => 'utf8',
            'collation' => 'utf8_unicode_ci'
        ]
    ],
];

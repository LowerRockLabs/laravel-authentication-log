<?php

return [
    // The database table name
    // You can change this if the database keys get too long for your driver
    'table_name' => 'authentication_log',

    // The database connection where the authentication_log table resides. Leave empty to use the default
    'db_connection' => null,

    // The events the package listens for to log
    'events' => [
        'login' => \Illuminate\Auth\Events\Login::class,
        'failed' => \Illuminate\Auth\Events\Failed::class,
        'logout' => \Illuminate\Auth\Events\Logout::class,
        'logout-other-devices' => \Illuminate\Auth\Events\OtherDeviceLogout::class,
    ],
    'use-client-header' => false,
    'client-header-ip' => '',
    'client-header-city' => "CF-IPCity",
    'client-header-country' => "CF-IPCountry",

    'notifications' => [
        'new-device' => [
            // Send the NewDevice notification
            'enabled' => env('NEW_DEVICE_NOTIFICATION', true),

            // Use torann/geoip to attempt to get a location
            'location' => false,

            // Use header to attempt to get a location
            'headerlocation' => true,

            // The Notification class to send
            'template' => App\Notifications\Alerts\NewDevice::class,
        ],
        'failed-login' => [
            // Send the FailedLogin notification
            'enabled' => env('FAILED_LOGIN_NOTIFICATION', true),

            // Use torann/geoip to attempt to get a location
            'location' => false,

            'headerlocation' => true,


            // The Notification class to send
            'template' => App\Notifications\Alerts\FailedLogin::class,
        ],
    ],

    // When the clean-up command is run, delete old logs greater than `purge` days
    // Don't schedule the clean-up command if you want to keep logs forever.
    'purge' => 365,
];

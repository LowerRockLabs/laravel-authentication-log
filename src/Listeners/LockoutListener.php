<?php

namespace Rappasoft\LaravelAuthenticationLog\Listeners;

use Illuminate\Auth\Events\Lockout;
use Illuminate\Http\Request;
use Rappasoft\LaravelAuthenticationLog\Notifications\FailedLogin;

class LockoutListener
{
    public Request $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    public function handle($event): void
    {
        $listener = config('authentication-log.events.lockout', Lockout::class);
        if (! $event instanceof $listener) {
            return;
        }

        $ip = (config('authentication-log.use-client-header')) ? request()->header(config('authentication-log.client-header-ip')) : request()->ip();

        $locationString = (config('authentication-log.notifications.failed-login.headerlocation')) ?
            ["City" => request()->header(config('authentication-log.client-header-city')),
             "Country" => request()->header(config('authentication-log.client-header-country'))] : ((config('authentication-log.notifications.failed-login.location')) ? optional(geoip()->getLocation($ip))->toArray() : null);


        //config('authentication-log.notifications.new-device.location') ? optional(geoip()->getLocation($ip))->toArray() : null,
        if ($event->user) {
            //$ip = request()->header('X-Forwarded-For');
            $log = $event->user->authentications()->create([
                'ip_address' => $ip,
                'user_agent' => $this->request->userAgent(),
                'login_at' => now(),
                'login_successful' => false,
                'location' => $locationString,
            ]);

            if (config('authentication-log.notifications.failed-login.enabled')) {
                $failedLogin = config('authentication-log.notifications.failed-login.template') ?? FailedLogin::class;
                $event->user->notify(new $failedLogin($log));
            }
        }
    }
}

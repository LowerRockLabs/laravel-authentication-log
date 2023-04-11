<?php

namespace Rappasoft\LaravelAuthenticationLog\Listeners;

use Illuminate\Auth\Events\Login;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Rappasoft\LaravelAuthenticationLog\Notifications\NewDevice;

class LoginListener
{
    public Request $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    public function handle($event): void
    {
        $listener = config('authentication-log.events.login', Login::class);
        if (! $event instanceof $listener) {
            return;
        }

        if ($event->user) {

            $ip = (config('authentication-log.use-client-header')) ? request()->header(config('authentication-log.client-header-ip')) : request()->ip();

            $locationString = (config('authentication-log.notifications.failed-login.headerlocation')) ?
                ["City" => request()->header(config('authentication-log.client-header-city')),
                 "Country" => request()->header(config('authentication-log.client-header-country'))] : ((config('authentication-log.notifications.failed-login.location')) ? optional(geoip()->getLocation($ip))->toArray() : null);

            $user = $event->user;
            $userAgent = $this->request->userAgent();
            $known = $user->authentications()->whereIpAddress($ip)->whereUserAgent($userAgent)->whereLoginSuccessful(true)->first();
            $newUser = Carbon::parse($user->{$user->getCreatedAtColumn()})->diffInMinutes(Carbon::now()) < 1;

            $log = $user->authentications()->create([
                'ip_address' => $ip,
                'user_agent' => $userAgent,
                'login_at' => now(),
                'login_successful' => true,
                'location' => $locationString,
            ]);

            if (! $known && ! $newUser && config('authentication-log.notifications.new-device.enabled')) {
                $newDevice = config('authentication-log.notifications.new-device.template') ?? NewDevice::class;
                $user->notify(new $newDevice($log));
            }
        }
    }
}

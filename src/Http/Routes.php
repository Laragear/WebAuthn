<?php

namespace Laragear\WebAuthn\Http;

use Illuminate\Routing\RouteRegistrar;
use Illuminate\Support\Facades\Route;

class Routes
{
    /**
     * Registers a set of default WebAuthn routes.
     */
    public static function register(
        string $attest = 'webauthn/register',
        string $attestController = 'App\Http\Controllers\WebAuthn\WebAuthnRegisterController',
        string $assert = 'webauthn/login',
        string $assertController = 'App\Http\Controllers\WebAuthn\WebAuthnLoginController',
    ): RouteRegistrar {
        return Route::middleware('web')
            ->group(static function () use ($assert, $assertController, $attest, $attestController): void {
                Route::controller($attestController)
                    ->group(static function () use ($attest): void {
                        Route::post("$attest/options", 'options')->name('webauthn.register.options');
                        Route::post("$attest", 'register')->name('webauthn.register');
                    });

                Route::controller($assertController)
                    ->group(static function () use ($assert): void {
                        Route::post("$assert/options", 'options')->name('webauthn.login.options');
                        Route::post("$assert", 'login')->name('webauthn.login');
                    });
            });
    }

    /**
     * Registers a set of default WebAuthn routes.
     *
     * @return void
     */
    public static function routes(): void
    {
        static::register();
    }
}

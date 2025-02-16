<?php

namespace Laragear\WebAuthn\Http;

use Illuminate\Routing\RouteRegistrar;

use function app;

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
        $router = app('router');

        return $router->middleware('web')
            ->group(static function () use ($router, $assert, $assertController, $attest, $attestController): void {
                $router->controller($attestController)
                    ->group(static function () use ($router, $attest): void {
                        $router->post("$attest/options", 'options')->name('webauthn.register.options');
                        $router->post("$attest", 'register')->name('webauthn.register');
                    });

                $router->controller($assertController)
                    ->group(static function () use ($router, $assert): void {
                        $router->post("$assert/options", 'options')->name('webauthn.login.options');
                        $router->post("$assert", 'login')->name('webauthn.login');
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

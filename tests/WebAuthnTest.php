<?php

namespace Tests;

use Illuminate\Support\Facades\Route;
use Laragear\WebAuthn\WebAuthn;

class WebAuthnTest extends TestCase
{
    protected function defineWebRoutes($router): void
    {
        WebAuthn::routes();
    }

    public function test_registers_webauthn_routes(): void
    {
        static::assertTrue(Route::has('webauthn.register.options'));
        static::assertTrue(Route::has('webauthn.register'));

        static::assertTrue(Route::has('webauthn.login.options'));
        static::assertTrue(Route::has('webauthn.login'));
    }
}

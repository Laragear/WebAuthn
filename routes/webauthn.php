<?php

use App\Http\Controllers\WebAuthn\WebAuthnLoginController;
use App\Http\Controllers\WebAuthn\WebAuthnRegisterController;
use Illuminate\Support\Facades\Route;

Route::middleware('web')
    ->group(static function (): void {
        Route::controller(WebAuthnRegisterController::class)
            ->group(static function (): void {
                Route::post('webauthn/register/options', 'options')->name('webauthn.register.options');
                Route::post('webauthn/register', 'register')->name('webauthn.register');
            });

        Route::controller(WebAuthnLoginController::class)
            ->group(static function (): void {
                Route::post('webauthn/login/options', 'options')->name('webauthn.login.options');
                Route::post('webauthn/login', 'login')->name('webauthn.login');
            });
    });

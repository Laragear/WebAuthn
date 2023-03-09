<?php

namespace Laragear\WebAuthn;

use Illuminate\Support\Facades\Route;

class WebAuthn
{
    // Constants for user verification in Attestation and Assertion.
    public const USER_VERIFICATION_PREFERRED = 'preferred';
    public const USER_VERIFICATION_DISCOURAGED = 'discouraged';
    public const USER_VERIFICATION_REQUIRED = 'required';

    // Attestation variables to limit the authenticator conveyance.
    public const PLATFORMS = ['cross-platform', 'platform'];
    public const TRANSPORTS = ['usb', 'nfc', 'ble', 'internal'];
    public const FORMATS = ['none', 'android-key', 'android-safetynet', 'apple', 'fido-u2f', 'packed', 'tpm'];

    // Resident Keys requirement.
    public const RESIDENT_KEY_REQUIRED = 'required';
    public const RESIDENT_KEY_PREFERRED = 'preferred';
    public const RESIDENT_KEY_DISCOURAGED = 'discouraged';

    /**
     * Registers a set of default WebAuthn routes.
     *
     * @return void
     */
    public static function routes(): void
    {
        Route::middleware('web')
            ->group(static function (): void {
                Route::controller(\App\Http\Controllers\WebAuthn\WebAuthnRegisterController::class)
                    ->group(static function (): void {
                        Route::post('webauthn/register/options', 'options')->name('webauthn.register.options');
                        Route::post('webauthn/register', 'register')->name('webauthn.register');
                    });

                Route::controller(\App\Http\Controllers\WebAuthn\WebAuthnLoginController::class)
                    ->group(static function (): void {
                        Route::post('webauthn/login/options', 'options')->name('webauthn.login.options');
                        Route::post('webauthn/login', 'login')->name('webauthn.login');
                    });
        });
    }
}

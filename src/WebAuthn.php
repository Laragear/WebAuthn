<?php

namespace Laragear\WebAuthn;

/**
 * @internal
 */
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
     * Returns all user verifications flags possible.
     *
     * @return string[]
     */
    public static function userVerifications(): array
    {
        return [
            static::USER_VERIFICATION_REQUIRED,
            static::USER_VERIFICATION_PREFERRED,
            static::USER_VERIFICATION_DISCOURAGED,
        ];
    }
}

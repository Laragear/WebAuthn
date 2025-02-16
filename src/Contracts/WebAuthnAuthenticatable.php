<?php

namespace Laragear\WebAuthn\Contracts;

use Illuminate\Database\Eloquent\Relations\MorphMany;
use Laragear\WebAuthn\Models\WebAuthnCredential;
use Laragear\WebAuthn\WebAuthnData;
use Ramsey\Uuid\UuidInterface;

interface WebAuthnAuthenticatable
{
    /**
     * Returns displayable data to be used to create WebAuthn Credentials.
     */
    public function webAuthnData(): WebAuthnData;

    /**
     * An anonymized user identity string, as a UUID.
     *
     * @see https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-id
     */
    public function webAuthnId(): UuidInterface;

    /**
     * Removes all credentials previously registered.
     */
    public function flushCredentials(string ...$except): void;

    /**
     * Disables all credentials for the user.
     */
    public function disableAllCredentials(string ...$except): void;

    /**
     * Makes an instance of a WebAuthn Credential attached to this user.
     */
    public function makeWebAuthnCredential(array $properties): WebAuthnCredential;

    /**
     * Returns a queryable relationship for its WebAuthn Credentials.
     */
    public function webAuthnCredentials(): MorphMany;
}

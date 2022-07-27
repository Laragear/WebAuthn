<?php

namespace Laragear\WebAuthn\Contracts;

use Illuminate\Database\Eloquent\Relations\MorphMany;
use Laragear\WebAuthn\Models\WebAuthnCredential;

interface WebAuthnAuthenticatable
{
    /**
     * Returns displayable data to be used to create WebAuthn Credentials.
     *
     * @return array{name: string, displayName: string}
     */
    public function webAuthnData(): array;

    /**
     * Removes all credentials previously registered.
     *
     * @param  string  ...$except
     * @return void
     */
    public function flushCredentials(string ...$except): void;

    /**
     * Disables all credentials for the user.
     *
     * @param  string  ...$except
     * @return void
     */
    public function disableAllCredentials(string ...$except): void;

    /**
     * Makes an instance of a WebAuthn Credential attached to this user.
     *
     * @param  array  $properties
     * @return \Laragear\WebAuthn\Models\WebAuthnCredential
     */
    public function makeWebAuthnCredential(array $properties): WebAuthnCredential;

    /**
     * Returns a queryable relationship for its WebAuthn Credentials.
     *
     * @phpstan-ignore-next-line
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany|\Laragear\WebAuthn\Models\WebAuthnCredential
     */
    public function webAuthnCredentials(): MorphMany;
}

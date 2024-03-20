<?php

namespace Laragear\WebAuthn\Assertion\Creator;

use Illuminate\Database\Eloquent\Collection;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\Enums\UserVerification;
use Laragear\WebAuthn\JsonTransport;

class AssertionCreation
{
    /**
     * Create a new Assertion Creation instance.
     */
    public function __construct(
        public ?WebAuthnAuthenticatable $user = null,
        public ?Collection $acceptedCredentials = null,
        public ?UserVerification $userVerification = null,
        public JsonTransport $json = new JsonTransport(),
    ) {
        //
    }
}

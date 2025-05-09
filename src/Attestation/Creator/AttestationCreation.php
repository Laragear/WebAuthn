<?php

namespace Laragear\WebAuthn\Attestation\Creator;

use Closure;
use Laragear\WebAuthn\Challenge\Challenge;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\Enums\ResidentKey;
use Laragear\WebAuthn\Enums\UserVerification;
use Laragear\WebAuthn\JsonTransport;

class AttestationCreation
{
    /**
     * Create a new Attestation Creation instance.
     *
     * @param  (\Closure(\Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable, bool):\Laragear\WebAuthn\WebAuthnData)|null  $using
     */
    public function __construct(
        public ?WebAuthnAuthenticatable $user,
        public ?Challenge $challenge = null,
        public ?Closure $using = null,
        public ResidentKey $residentKey = ResidentKey::Preferred,
        public UserVerification $userVerification = UserVerification::Preferred,
        public JsonTransport $json = new JsonTransport(),
        public bool $uniqueCredentials = true,
    ) {
        //
    }
}

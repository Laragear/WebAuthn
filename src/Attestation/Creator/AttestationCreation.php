<?php

namespace Laragear\WebAuthn\Attestation\Creator;

use Illuminate\Http\Request;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\Enums\ResidentKey;
use Laragear\WebAuthn\Enums\UserVerification;
use Laragear\WebAuthn\JsonTransport;

class AttestationCreation
{
    /**
     * Create a new Attestation Instructions instance.
     */
    public function __construct(
        public WebAuthnAuthenticatable $user,
        public Request $request,
        public ?ResidentKey $residentKey = null,
        public ?UserVerification $userVerification = null,
        public bool $uniqueCredentials = true,
        public JsonTransport $json = new JsonTransport()
    ) {
        //
    }
}

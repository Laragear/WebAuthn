<?php

namespace Laragear\WebAuthn\Assertion\Validator;

use Laragear\WebAuthn\Attestation\AuthenticatorData;
use Laragear\WebAuthn\Challenge;
use Laragear\WebAuthn\ClientDataJson;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\JsonTransport;
use Laragear\WebAuthn\Models\WebAuthnCredential;

class AssertionValidation
{
    /**
     * Create a new Assertion Validation.
     */
    public function __construct(
        public JsonTransport $request,
        public ?WebAuthnAuthenticatable $user = null,
        public ?Challenge $challenge = null,
        public ?WebAuthnCredential $credential = null,
        public ?ClientDataJson $clientDataJson = null,
        public ?AuthenticatorData $authenticatorData = null,
    ) {
        //
    }
}

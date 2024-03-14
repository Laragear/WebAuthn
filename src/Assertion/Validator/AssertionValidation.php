<?php

namespace Laragear\WebAuthn\Assertion\Validator;

use Illuminate\Http\Request;
use Laragear\WebAuthn\Attestation\AuthenticatorData;
use Laragear\WebAuthn\Challenge;
use Laragear\WebAuthn\ClientDataJson;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\Models\WebAuthnCredential;

class AssertionValidation
{
    /**
     * Create a new Assertion Validation.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable|null  $user
     * @param  \Laragear\WebAuthn\Challenge|null  $challenge
     * @param  \Laragear\WebAuthn\Models\WebAuthnCredential|null  $credential
     * @param  \Laragear\WebAuthn\ClientDataJson|null  $clientDataJson
     * @param  \Laragear\WebAuthn\Attestation\AuthenticatorData|null  $authenticatorData
     */
    public function __construct(
        public Request $request,
        public ?WebAuthnAuthenticatable $user = null,
        public ?Challenge $challenge = null,
        public ?WebAuthnCredential $credential = null,
        public ?ClientDataJson $clientDataJson = null,
        public ?AuthenticatorData $authenticatorData = null,
    ) {
        //
    }
}

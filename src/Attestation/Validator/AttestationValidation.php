<?php

namespace Laragear\WebAuthn\Attestation\Validator;

use Illuminate\Http\Request;
use Laragear\WebAuthn\Attestation\AttestationObject;
use Laragear\WebAuthn\Challenge;
use Laragear\WebAuthn\ClientDataJson;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\Models\WebAuthnCredential;

class AttestationValidation
{
    /**
     * Create a new Attestation Validation procedure
     *
     * @param  \Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable  $user
     * @param  \Illuminate\Http\Request  $request
     * @param  \Laragear\WebAuthn\Challenge|null  $challenge
     * @param  \Laragear\WebAuthn\Attestation\AttestationObject|null  $attestationObject
     * @param  \Laragear\WebAuthn\ClientDataJson|null  $clientDataJson
     * @param  \Laragear\WebAuthn\Models\WebAuthnCredential|null  $credential
     */
    public function __construct(
        public WebAuthnAuthenticatable $user,
        public Request $request,
        public ?Challenge $challenge = null,
        public ?AttestationObject $attestationObject = null,
        public ?ClientDataJson $clientDataJson = null,
        public ?WebAuthnCredential $credential = null,
    )
    {
        //
    }
}

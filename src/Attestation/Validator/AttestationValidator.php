<?php

namespace Laragear\WebAuthn\Attestation\Validator;

use Illuminate\Pipeline\Pipeline;

/**
 * @see https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
 *
 * @method \Laragear\WebAuthn\Attestation\Validator\AttestationValidation thenReturn()
 */
class AttestationValidator extends Pipeline
{
    /**
     * The array of class pipes.
     *
     * @var array
     */
    protected $pipes = [
        Pipes\RetrieveChallenge::class,
        Pipes\CompileClientDataJson::class,
        Pipes\CompileAttestationObject::class,
        Pipes\AttestationIsForCreation::class,
        Pipes\CheckChallengeSame::class,
        Pipes\CheckOriginSecure::class,
        Pipes\CheckRelyingPartyIdContained::class,
        Pipes\CheckRelyingPartyHashSame::class,
        Pipes\CheckUserInteraction::class,
        Pipes\CredentialIdShouldNotBeDuplicated::class,
        Pipes\MakeWebAuthnCredential::class,
    ];
}

<?php

namespace Laragear\WebAuthn\Attestation\Creator;

use Illuminate\Pipeline\Pipeline;

/**
 * @see https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
 *
 * @method \Laragear\WebAuthn\Assertion\Creator\AssertionCreation thenReturn()
 */
class AttestationCreator extends Pipeline
{
    /**
     * The array of class pipes.
     *
     * @var array
     */
    protected $pipes = [
        Pipes\AddRelyingParty::class,
        Pipes\SetResidentKeyConfiguration::class,
        Pipes\MayRequireUserVerification::class,
        Pipes\AddUserDescriptor::class,
        Pipes\AddAcceptedAlgorithms::class,
        Pipes\MayPreventDuplicateCredentials::class,
        Pipes\CreateAttestationChallenge::class,
    ];
}

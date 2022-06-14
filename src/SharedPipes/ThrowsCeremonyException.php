<?php

namespace Laragear\WebAuthn\SharedPipes;

use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;
use Laragear\WebAuthn\Exceptions\AssertionException;
use Laragear\WebAuthn\Exceptions\AttestationException;

/**
 * @internal
 */
trait ThrowsCeremonyException
{
    /**
     * Throws an exception for the validation.
     *
     * @param  \Laragear\WebAuthn\Attestation\Validator\AttestationValidation|\Laragear\WebAuthn\Assertion\Validator\AssertionValidation  $validation
     * @param  string  $message
     * @return void&never
     * @throws \Laragear\WebAuthn\Exceptions\AssertionException|\Laragear\WebAuthn\Exceptions\AttestationException
     */
    protected static function throw(AttestationValidation|AssertionValidation $validation, string $message): void
    {
        throw $validation instanceof AssertionValidation
            ? AssertionException::make($message)
            : AttestationException::make($message);
    }
}

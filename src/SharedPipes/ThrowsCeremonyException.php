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
     */
    protected static function throw(AttestationValidation|AssertionValidation $validation, string $message): never
    {
        throw $validation instanceof AssertionValidation
            ? AssertionException::make($message)
            : AttestationException::make($message);
    }
}

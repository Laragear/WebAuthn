<?php

namespace Laragear\WebAuthn\SharedPipes;

use Closure;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;

/**
 * @internal
 */
abstract class CheckChallengeSame
{
    use ThrowsCeremonyException;

    /**
     * Handle the incoming WebAuthn Ceremony Validation.
     *
     * @throws \Laragear\WebAuthn\Exceptions\AssertionException
     * @throws \Laragear\WebAuthn\Exceptions\AttestationException
     */
    public function handle(AttestationValidation|AssertionValidation $validation, Closure $next): mixed
    {
        if ($validation->clientDataJson->challenge->hasNoLength()) {
            static::throw($validation, 'Response has an empty challenge.');
        }

        if ($validation->clientDataJson->challenge->hashNotEqual($validation->challenge->data)) {
            static::throw($validation, 'Response challenge is not equal.');
        }

        return $next($validation);
    }
}

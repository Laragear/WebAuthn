<?php

namespace Laragear\WebAuthn\SharedPipes;

use Closure;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;

/**
 * @internal
 */
abstract class CheckUserInteraction
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
        $notPresent = $validation instanceof AttestationValidation
            ? $validation->attestationObject->authenticatorData->wasUserAbsent()
            : $validation->authenticatorData->wasUserAbsent();

        if ($notPresent) {
            static::throw($validation, 'Response did not have the user present.');
        }

        // Only verify the user if the challenge required it.
        if ($validation->challenge->verify) {
            $notVerified = $validation instanceof AttestationValidation
                ? $validation->attestationObject->authenticatorData->wasUserNotVerified()
                : $validation->authenticatorData->wasUserNotVerified();

            if ($notVerified) {
                static::throw($validation, 'Response did not verify the user.');
            }
        }

        return $next($validation);
    }
}

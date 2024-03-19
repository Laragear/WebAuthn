<?php

namespace Laragear\WebAuthn\SharedPipes;

use Closure;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;
use Laragear\WebAuthn\ChallengeRepository;

/**
 * This should be the first pipe to run, as the Challenge may expire by mere milliseconds.
 *
 * @internal
 */
abstract class RetrieveChallenge
{
    use ThrowsCeremonyException;

    /**
     * Create a new pipe instance.
     */
    public function __construct(protected ChallengeRepository $challenge)
    {
        //
    }

    /**
     * Handle the incoming Assertion Validation.
     */
    public function handle(AttestationValidation|AssertionValidation $validation, Closure $next): mixed
    {
        if ($validation->challenge = $this->challenge->pull()) {
            return $next($validation);
        }

        static::throw($validation, 'Challenge does not exist.');
    }
}

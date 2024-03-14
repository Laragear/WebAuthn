<?php

namespace Laragear\WebAuthn\SharedPipes;

use Closure;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;
use Laragear\WebAuthn\Challenge;

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
    public function __construct(protected Repository $config)
    {
        //
    }

    /**
     * Handle the incoming Assertion Validation.
     */
    public function handle(AttestationValidation|AssertionValidation $validation, Closure $next): mixed
    {
        $validation->challenge = $this->retrieveChallenge($validation->request);

        if (! $validation->challenge) {
            static::throw($validation, 'Challenge does not exist.');
        }

        return $next($validation);
    }

    /**
     * Pulls an Attestation challenge from the Cache.
     */
    protected function retrieveChallenge(Request $request): ?Challenge
    {
        /** @var \Laragear\WebAuthn\Challenge|null $challenge */
        $challenge = $request->session()->pull($this->config->get('webauthn.challenge.key'));

        if (! $challenge || $challenge->hasExpired()) {
            return null;
        }

        return $challenge;
    }
}

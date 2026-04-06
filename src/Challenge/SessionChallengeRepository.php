<?php

namespace Laragear\WebAuthn\Challenge;

use Illuminate\Contracts\Config\Repository as ConfigContract;
use Illuminate\Contracts\Session\Session as SessionContract;
use Laragear\WebAuthn\Assertion\Creator\AssertionCreation;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreation;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;
use Laragear\WebAuthn\Contracts\WebAuthnChallengeRepository;

use function is_array;

/**
 * @internal
 */
class SessionChallengeRepository implements WebAuthnChallengeRepository
{
    /**
     * Create a new challenge repository instance.
     */
    public function __construct(protected SessionContract $session, protected ConfigContract $config)
    {
        //
    }

    /**
     * Puts a ceremony challenge into the repository.
     */
    public function store(AttestationCreation|AssertionCreation $ceremony, Challenge $challenge): void
    {
        $this->session->put($this->config->get('webauthn.challenge.key'), $challenge);
    }

    /**
     * Pulls out a challenge instance from the session.
     *
     * It will not return if it has expired not expired.
     */
    public function pull(AttestationValidation|AssertionValidation $ceremony): ?Challenge
    {
        /** @var \Laragear\WebAuthn\Challenge\Challenge|array|null $challenge */
        $challenge = $this->session->pull($this->config->get('webauthn.challenge.key'));

        if (is_array($challenge)) {
            $challenge = Challenge::fromArray($challenge);
        }

        // Only return the challenge if it's valid (not expired)
        if ($challenge?->isValid()) {
            return $challenge;
        }

        return null;
    }
}

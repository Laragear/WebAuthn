<?php

namespace Laragear\WebAuthn;

use Illuminate\Contracts\Config\Repository as ConfigContract;
use Illuminate\Contracts\Session\Session as SessionContract;
use Laragear\WebAuthn\Enums\UserVerification;

class ChallengeRepository
{
    /**
     * Create a new challenge repository instance.
     */
    public function __construct(protected SessionContract $session, protected ConfigContract $config)
    {
    }

    /**
     * Creates a challenge instance into the session using the given options.
     */
    public function store(?UserVerification $verify, array $options = []): Challenge
    {
        $challenge = Challenge::random(
            $this->config->get('webauthn.challenge.bytes'),
            $this->config->get('webauthn.challenge.timeout'),
            $verify === UserVerification::REQUIRED,
            $options,
        );

        $this->session->put($this->config->get('webauthn.challenge.key'), $challenge);

        return $challenge;
    }

    /**
     * Pulls out a challenge instance from the session.
     *
     * It will not return if it has expired not expired.
     */
    public function pull(): ?Challenge
    {
        /** @var \Laragear\WebAuthn\Challenge $challenge */
        $challenge = $this->session->pull($this->config->get('webauthn.challenge.key'));

        // Only return the challenge if it's valid (not expired)
        if ($challenge?->isValid()) {
            return $challenge;
        }

        return null;
    }
}

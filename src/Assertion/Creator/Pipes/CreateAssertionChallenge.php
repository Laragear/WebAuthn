<?php

namespace Laragear\WebAuthn\Assertion\Creator\Pipes;

use Closure;
use Illuminate\Config\Repository as ConfigContract;
use Laragear\WebAuthn\Assertion\Creator\AssertionCreation;
use Laragear\WebAuthn\Challenge\Challenge;
use Laragear\WebAuthn\Contracts\WebAuthnChallengeRepository as ChallengeRepositoryContract;
use Laragear\WebAuthn\Enums\UserVerification;
use Laragear\WebAuthn\Models\WebAuthnCredential;

class CreateAssertionChallenge
{
    /**
     * Create a new pipe instance.
     */
    public function __construct(protected ChallengeRepositoryContract $challenge, protected ConfigContract $config)
    {
        //
    }

    /**
     * Handle the incoming Assertion.
     *
     * @throws \Random\RandomException
     */
    public function handle(AssertionCreation $assertion, Closure $next): mixed
    {
        $assertion->challenge ??= Challenge::random(
            $this->config->get('webauthn.challenge.bytes'),
            $this->config->get('webauthn.challenge.timeout'),
        );

        $assertion->challenge->verify = $assertion->userVerification === UserVerification::Required;

        if ($assertion->acceptedCredentials?->isNotEmpty()) {
            $assertion->challenge->properties['credentials'] = $assertion->acceptedCredentials
                ->map(static function (WebAuthnCredential $credential): string {
                    return $credential->getKey();
                })->toArray();
        }

        $assertion->json->set('challenge', $assertion->challenge->data);

        $this->challenge->store($assertion, $assertion->challenge);

        return $next($assertion);
    }
}

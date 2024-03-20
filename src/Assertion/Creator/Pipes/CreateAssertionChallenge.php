<?php

namespace Laragear\WebAuthn\Assertion\Creator\Pipes;

use Closure;
use Laragear\WebAuthn\Assertion\Creator\AssertionCreation;
use Laragear\WebAuthn\ChallengeRepository;

class CreateAssertionChallenge
{
    /**
     * Create a new pipe instance.
     */
    public function __construct(protected ChallengeRepository $challenge)
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
        $options = [];

        if ($assertion->acceptedCredentials?->isNotEmpty()) {
            // @phpstan-ignore-next-line
            $options['credentials'] = $assertion->acceptedCredentials->map->getKey()->toArray();
        }

        $assertion->json->set('challenge', $this->challenge->store($assertion->userVerification, $options)->data);

        return $next($assertion);
    }
}

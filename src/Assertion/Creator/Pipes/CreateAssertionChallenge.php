<?php

namespace Laragear\WebAuthn\Assertion\Creator\Pipes;

use Closure;
use Illuminate\Contracts\Config\Repository;
use Laragear\WebAuthn\Assertion\Creator\AssertionCreation;
use Laragear\WebAuthn\Attestation\SessionChallenge;

class CreateAssertionChallenge
{
    use SessionChallenge;

    /**
     * Create a new pipe instance.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(protected Repository $config)
    {
        //
    }

    /**
     * Handle the incoming Assertion.
     *
     * @param  \Laragear\WebAuthn\Assertion\Creator\AssertionCreation  $assertion
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(AssertionCreation $assertion, Closure $next): mixed
    {
        $options = [];

        if ($assertion->acceptedCredentials?->isNotEmpty()) {
            // @phpstan-ignore-next-line
            $options['credentials'] = $assertion->acceptedCredentials->map->getKey()->toArray();
        }

        $challenge = $this->storeChallenge($assertion->request, $assertion->userVerification, $options);

        $assertion->json->set('challenge', $challenge->data);

        return $next($assertion);
    }
}

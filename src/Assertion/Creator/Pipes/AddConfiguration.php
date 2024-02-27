<?php

namespace Laragear\WebAuthn\Assertion\Creator\Pipes;

use Closure;
use Illuminate\Contracts\Config\Repository;
use Laragear\WebAuthn\Assertion\Creator\AssertionCreation;

class AddConfiguration
{
    /**
     * Create a new pipe instance.
     */
    public function __construct(protected Repository $config)
    {
        //
    }

    /**
     * Handle the incoming Assertion.
     */
    public function handle(AssertionCreation $assertion, Closure $next): mixed
    {
        $assertion->json->set('timeout', $this->config->get('webauthn.challenge.timeout') * 1000);

        return $next($assertion);
    }
}

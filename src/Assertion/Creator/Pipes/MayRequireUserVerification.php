<?php

namespace Laragear\WebAuthn\Assertion\Creator\Pipes;

use Closure;
use Laragear\WebAuthn\Assertion\Creator\AssertionCreation;

class MayRequireUserVerification
{
    /**
     * Handle the incoming Assertion.
     */
    public function handle(AssertionCreation $assertion, Closure $next): mixed
    {
        if ($assertion->userVerification) {
            $assertion->json->set('userVerification', $assertion->userVerification->value);
        }

        return $next($assertion);
    }
}

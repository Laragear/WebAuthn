<?php

namespace Laragear\WebAuthn\Assertion\Creator\Pipes;

use Closure;
use Laragear\WebAuthn\Assertion\Creator\AssertionCreation;

class MayRequireUserVerification
{
    /**
     * Handle the incoming Assertion.
     *
     * @param  \Laragear\WebAuthn\Assertion\Creator\AssertionCreation  $assertion
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(AssertionCreation $assertion, Closure $next): mixed
    {
        if ($assertion->userVerification) {
            $assertion->json->set('userVerification', $assertion->userVerification);
        }

        return $next($assertion);
    }
}

<?php

namespace Laragear\WebAuthn\Assertion\Validator\Pipes;

use Closure;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Exceptions\AssertionException;

/**
 * @internal
 */
class CheckTypeIsPublicKey
{
    /**
     * Handle the incoming Assertion Validation.
     *
     * @throws \Laragear\WebAuthn\Exceptions\AssertionException
     */
    public function handle(AssertionValidation $validation, Closure $next): mixed
    {
        if ($validation->request->json('type') !== 'public-key') {
            throw AssertionException::make('Response type is not [public-key].');
        }

        return $next($validation);
    }
}

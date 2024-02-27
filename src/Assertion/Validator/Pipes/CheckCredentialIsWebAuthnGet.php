<?php

namespace Laragear\WebAuthn\Assertion\Validator\Pipes;

use Closure;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Exceptions\AssertionException;

/**
 * @internal
 */
class CheckCredentialIsWebAuthnGet
{
    /**
     * Handle the incoming Assertion Validation.
     *
     * @throws \Laragear\WebAuthn\Exceptions\AssertionException
     */
    public function handle(AssertionValidation $validation, Closure $next): mixed
    {
        if ($validation->clientDataJson->type !== 'webauthn.get') {
            throw AssertionException::make('Client Data type is not [webauthn.get].');
        }

        return $next($validation);
    }
}

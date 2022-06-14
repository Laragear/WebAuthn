<?php

namespace Laragear\WebAuthn\Assertion\Validator\Pipes;

use Closure;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Attestation\AuthenticatorData;
use Laragear\WebAuthn\Exceptions\AssertionException;
use Laragear\WebAuthn\Exceptions\DataException;
use function base64_decode;

/**
 * @internal
 */
class CompileAuthenticatorData
{
    /**
     * Handle the incoming Assertion Validation.
     *
     * @param  \Laragear\WebAuthn\Assertion\Validator\AssertionValidation  $validation
     * @param  \Closure  $next
     * @return mixed
     * @throws \Laragear\WebAuthn\Exceptions\AssertionException
     */
    public function handle(AssertionValidation $validation, Closure $next): mixed
    {
        $data = base64_decode($validation->request->json('response.authenticatorData', ''));

        if (!$data) {
            throw AssertionException::make('Authenticator Data does not exist or is empty.');
        }

        try {
            $validation->authenticatorData = AuthenticatorData::fromBinary($data);
        } catch (DataException $e) {
            throw AssertionException::make($e->getMessage());
        }

        return $next($validation);
    }
}

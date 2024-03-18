<?php

namespace Laragear\WebAuthn\Assertion\Validator\Pipes;

use Closure;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Attestation\AuthenticatorData;
use Laragear\WebAuthn\ByteBuffer;
use Laragear\WebAuthn\Exceptions\AssertionException;
use Laragear\WebAuthn\Exceptions\DataException;

/**
 * @internal
 */
class CompileAuthenticatorData
{
    /**
     * Handle the incoming Assertion Validation.
     *
     * @throws \Laragear\WebAuthn\Exceptions\AssertionException
     */
    public function handle(AssertionValidation $validation, Closure $next): mixed
    {
        $data = ByteBuffer::decodeBase64Url($validation->request->json('response.authenticatorData', ''));

        if (! $data) {
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

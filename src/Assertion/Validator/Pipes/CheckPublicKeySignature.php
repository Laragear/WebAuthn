<?php

namespace Laragear\WebAuthn\Assertion\Validator\Pipes;

use Closure;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Exceptions\AssertionException;
use OpenSSLAsymmetricKey;
use Safe\Exceptions\OpensslException;

use function Safe\base64_decode;
use function hash;
use function Safe\openssl_pkey_get_public;
use function Safe\openssl_verify;
use const OPENSSL_ALGO_SHA256;

/**
 * @internal
 */
class CheckPublicKeySignature
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
        try {
            $publicKey = openssl_pkey_get_public($validation->credential->public_key);
        } catch (OpensslException) {
            throw AssertionException::make('Stored Public Key is invalid.');
        }

        $signature = base64_decode($validation->request->json('response.signature', ''));

        if ($signature === '') {
            throw AssertionException::make('Signature is empty.');
        }

        $this->validateSignature($validation, $publicKey, $signature);

        return $next($validation);
    }

    /**
     * Validate the signature from the assertion.
     *
     * @param  \Laragear\WebAuthn\Assertion\Validator\AssertionValidation  $validation
     * @param  string    $signature
     * @param  resource  $publicKey
     * @return void
     * @throws \Laragear\WebAuthn\Exceptions\AssertionException
     */
    private function validateSignature(
        AssertionValidation $validation,
        $publicKey,
        string $signature
    ): void {
        $verifiable = base64_decode($validation->request->json('response.authenticatorData'))
            .hash('sha256', base64_decode($validation->request->json('response.clientDataJSON')), true);

        if (openssl_verify($verifiable, $signature, $publicKey, OPENSSL_ALGO_SHA256) !== 1) {
            throw AssertionException::make('Signature is invalid.');
        }
    }
}

<?php

namespace Laragear\WebAuthn\Assertion\Validator\Pipes;

use Closure;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Exceptions\AssertionException;
use OpenSSLAsymmetricKey;
use function base64_decode;
use function hash;
use function openssl_pkey_get_public;
use function openssl_verify;
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
        $publicKey = openssl_pkey_get_public($validation->credential->public_key);

        if (!$publicKey) {
            throw AssertionException::make('Stored Public Key is invalid.');
        }

        $signature = base64_decode($validation->request->json('response.signature', ''));

        if (!$signature) {
            throw AssertionException::make('Signature is empty.');
        }

        $this->validateSignature($validation, $publicKey, $signature);

        return $next($validation);
    }

    /**
     * Validate the signature from the assertion.
     *
     * @param  \Laragear\WebAuthn\Assertion\Validator\AssertionValidation  $validation
     * @param  string  $signature
     * @param  \OpenSSLAsymmetricKey  $publicKey
     * @return void
     * @throws \Laragear\WebAuthn\Exceptions\AssertionException
     */
    public function validateSignature(
        AssertionValidation $validation,
        OpenSSLAsymmetricKey $publicKey,
        string $signature
    ): void {
        $verifiable = base64_decode($validation->request->json('response.authenticatorData'))
            .hash('sha256', base64_decode($validation->request->json('response.clientDataJSON')), true);

        if (openssl_verify($verifiable, $signature, $publicKey, OPENSSL_ALGO_SHA256) !== 1) {
            throw AssertionException::make('Signature is invalid.');
        }
    }
}

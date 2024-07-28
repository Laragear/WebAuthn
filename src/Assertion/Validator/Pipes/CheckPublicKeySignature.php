<?php

namespace Laragear\WebAuthn\Assertion\Validator\Pipes;

use Closure;
use Illuminate\Support\Str;
use Illuminate\Support\Stringable;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\ByteBuffer;
use Laragear\WebAuthn\Exceptions\AssertionException;
use Laragear\WebAuthn\JsonTransport;
use Laragear\WebAuthn\Models\WebAuthnCredential;
use function base64_decode;
use function function_exists;
use function hash;
use function in_array;
use function openssl_error_string;
use function openssl_pkey_get_public;
use function openssl_verify;
use function strlen;
use const OPENSSL_ALGO_SHA256;

/**
 * @internal
 */
class CheckPublicKeySignature
{
    /**
     * Handle the incoming Assertion Validation.
     *
     * @throws \Laragear\WebAuthn\Exceptions\AssertionException
     */
    public function handle(AssertionValidation $validation, Closure $next): mixed
    {
        $signature = $this->retrieveSignature($validation->json);
        $verifiable = $this->retrieveBinaryVerifiable($validation->json);

        if ($this->challengeRequiresSodium($signature, $validation->credential)) {
            $this->validateWithSodium($signature, $verifiable, $validation->credential);
        } else {
            $this->validateWithOpenSsl($signature, $verifiable, $validation->credential);
        }

        return $next($validation);
    }

    /**
     * Retrieves the signature of the data created by the authenticator.
     */
    protected function retrieveSignature(JsonTransport $request): string
    {
        $signature = ByteBuffer::decodeBase64Url($request->get('response.signature', ''));

        return $signature
            ?: throw AssertionException::make('Signature is empty.');
    }

    /**
     * Returns the binary representation of the authenticator and client data from the authenticator.
     */
    protected function retrieveBinaryVerifiable(JsonTransport $request): string
    {
        $verifiable = ByteBuffer::decodeBase64Url($request->get('response.authenticatorData')).
            hash('sha256', ByteBuffer::decodeBase64Url($request->get('response.clientDataJSON')), true);

        return $verifiable
            ?: throw AssertionException::make('Authenticator Data or Client Data JSON are empty or malformed.');
    }

    /**
     * Check if the challenge is to be verified by an EdDSA 25519 public key.
     *
     * @see https://www.rfc-editor.org/rfc/rfc8410#section-10.1
     */
    protected function challengeRequiresSodium(string $signature, WebAuthnCredential $credential): bool
    {
        return function_exists('sodium_crypto_sign_verify_detached')
            // Double ensure the signature has the given key length.
            && 64 === strlen($signature)
            // Double-ensure the key has the length of a EdDSA 25519 public key.
            && in_array($this->extractKey($credential)->length(), [44, 60], true);
    }

    /**
     * Extracts the public key data from a PEM and returns it without header and footer.
     */
    protected function extractKey(WebAuthnCredential $credential): Stringable
    {
        return Str::of($credential->public_key)
            ->between('-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----')
            ->trim();
    }

    /**
     * Try to validate the WebAuthn data with Sodium (if installed).
     */
    protected function validateWithSodium(string $signature, string $verifiable, WebAuthnCredential $credential): void
    {
        try {
            $valid = \sodium_crypto_sign_verify_detached(
                // Remove any header from the public key, as the key is on the tail.
                $signature, $verifiable, base64_decode($this->extractKey($credential)->substr(-44))
            );
        } catch (\SodiumException $e) {
            throw AssertionException::make($e->getMessage());
        }

        if (! $valid) {
            throw AssertionException::make('Signature is invalid.');
        }
    }

    /**
     * Try to validate the WebAuthn data with OpenSSL.
     */
    protected function validateWithOpenSsl(string $signature, string $verifiable, WebAuthnCredential $credential): void
    {
        if (! $publicKey = openssl_pkey_get_public($credential->public_key)) {
            throw AssertionException::make('Public key is invalid: '.openssl_error_string());
        }

        if (openssl_verify($verifiable, $signature, $publicKey, OPENSSL_ALGO_SHA256) !== 1) {
            throw AssertionException::make('Signature is invalid: '.openssl_error_string());
        }
    }
}

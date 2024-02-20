<?php

namespace Laragear\WebAuthn\Auth;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidator;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\Exceptions\AssertionException;
use function class_implements;
use function config;
use function in_array;
use function logger;
use function request;

/**
 * This class is not meant to be used directly.
 *
 * @internal
 */
class WebAuthnUserProvider extends EloquentUserProvider
{
    /**
     * Create a new database user provider.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @param  string  $model
     * @param  \Laragear\WebAuthn\Assertion\Validator\AssertionValidator  $validator
     * @param  bool  $fallback
     */
    public function __construct(
        HasherContract $hasher,
        string $model,
        protected AssertionValidator $validator,
        protected bool $fallback,
    ) {
        parent::__construct($hasher, $model);
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array  $credentials
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByCredentials(array $credentials)
    {
        // If the user is WebAuthnAuthenticatable and the credentials are a signed Assertion
        // Challenge response, we wil find the user that has this Credential ID. Otherwise,
        // we will pass the credentials as-is to Laravel's vanilla Eloquent User Provider.
        if ($this->userIsWebAuthnAuthenticatable() && $this->isSignedChallenge($credentials)) {
            /** @noinspection PhpIncompatibleReturnTypeInspection */
            return $this->newModelQuery()
                ->whereHas('webAuthnCredentials', static function (Builder $query) use ($credentials): void {
                    // @phpstan-ignore-next-line
                    $query->whereKey($credentials['id'])->whereEnabled();
                })
                ->first();
        }

        return parent::retrieveByCredentials($credentials);
    }

    /**
     * Check if the user model implements the WebAuthnAuthenticatable interface.
     *
     * @return bool
     */
    protected function userIsWebAuthnAuthenticatable(): bool
    {
        return in_array(WebAuthnAuthenticatable::class, class_implements($this->model), true);
    }

    /**
     * Check if the credentials are for a public key signed challenge
     *
     * @param  array  $credentials
     * @return bool
     */
    protected function isSignedChallenge(array $credentials): bool
    {
        return isset($credentials['id'], $credentials['rawId'], $credentials['response'], $credentials['type']);
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable  $user
     * @param  array  $credentials
     *
     * @return bool
     */
    public function validateCredentials($user, array $credentials): bool
    {
        if ($user instanceof WebAuthnAuthenticatable && $this->isSignedChallenge($credentials)) {
            return $this->validateWebAuthn($user);
        }

        // If the fallback is enabled, we will validate the credential password.
        return $this->fallback && parent::validateCredentials($user, $credentials);
    }

    /**
     * Validate the WebAuthn assertion.
     *
     * @param  \Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable  $user
     * @return bool
     */
    protected function validateWebAuthn(WebAuthnAuthenticatable $user): bool
    {
        try {
            // When we hit this method, we already have the user for the credential, so we will
            // pass it to the Assertion Validation data, thus avoiding fetching it again.
            $this->validator->send(new AssertionValidation(request(), user: $user))->thenReturn();
        } catch (AssertionException $e) {
            // If we're debugging, like under local development, push the error to the logger.
            if (config('app.debug')) {
                logger($e->getMessage());
            }

            return false;
        }

        return true;
    }
}

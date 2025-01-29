<?php

namespace Laragear\WebAuthn\Auth;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable as UserContract;
use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidator;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\Exceptions\AssertionException;
use Laragear\WebAuthn\JsonTransport;

use function class_implements;
use function config;
use function in_array;
use function logger;

/**
 * This class is not meant to be used directly.
 *
 * @internal
 */
class WebAuthnUserProvider extends EloquentUserProvider
{
    /**
     * Create a new database user provider.
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
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByCredentials(array $credentials)
    {
        // If the user is WebAuthnAuthenticatable and the credentials are a signed Assertion
        // Challenge response, we will add a simple query to the Auth User Provider to find
        // the user for the Credential ID, while keeping the other credentials key values.
        if ($this->userIsWebAuthnAuthenticatable() && $this->isSignedChallenge($credentials)) {
            $id = $credentials['id'];

            unset($credentials['id'], $credentials['rawId'], $credentials['response'], $credentials['type']);

            $credentials = [...$credentials, static function (Builder $query) use ($id): void {
                $query->whereHas('webAuthnCredentials', static function (Builder $query) use ($id): void {
                    // @phpstan-ignore-next-line
                    $query->whereKey($id)->whereEnabled();
                });
            }];
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
     * Check if the credentials are for a public key signed challenge.
     */
    protected function isSignedChallenge(array $credentials): bool
    {
        return isset($credentials['id'], $credentials['rawId'], $credentials['response'], $credentials['type']);
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable  $user
     */
    public function validateCredentials($user, array $credentials): bool
    {
        if ($user instanceof WebAuthnAuthenticatable && $this->isSignedChallenge($credentials)) {
            return $this->validateWebAuthn($user, $credentials);
        }

        // If the fallback is enabled, we will validate the credential password.
        return $this->fallback && parent::validateCredentials($user, $credentials);
    }

    /**
     * Validate the WebAuthn assertion.
     */
    protected function validateWebAuthn(WebAuthnAuthenticatable $user, array $credentials): bool
    {
        try {
            // When we hit this method, we already have the user for the credential, so we will
            // pass it to the Assertion Validation data, thus avoiding fetching it again.
            $this->validator
                ->send(new AssertionValidation(new JsonTransport($credentials), $user))
                ->thenReturn();
        } catch (AssertionException $e) {
            // If we're debugging, like under local development, push the error to the logger.
            if (config('app.debug')) {
                logger($e->getMessage());
            }

            return false;
        }

        return true;
    }

    /**
     * Rehash the user's password if required and supported.
     */
    public function rehashPasswordIfRequired(UserContract $user, array $credentials, bool $force = false): void
    {
        // @phpstan-ignore-next-line
        if (! $this->isSignedChallenge($credentials) && method_exists(get_parent_class($this), 'rehashPasswordIfRequired')) {
            parent::rehashPasswordIfRequired($user, $credentials, $force);
        }
    }
}

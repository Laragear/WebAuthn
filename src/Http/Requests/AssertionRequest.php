<?php

namespace Laragear\WebAuthn\Http\Requests;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Auth;
use InvalidArgumentException;
use Laragear\WebAuthn\Assertion\Creator\AssertionCreation;
use Laragear\WebAuthn\Assertion\Creator\AssertionCreator;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\WebAuthn;
use function is_int;
use function is_string;

class AssertionRequest extends FormRequest
{
    /**
     * The Assertion Creation instance.
     *
     * @var \Laragear\WebAuthn\Assertion\Creator\AssertionCreation
     */
    protected AssertionCreation $assertion;

    /**
     * The guard to use to retrieve the user.
     *
     * @var string|null
     */
    protected ?string $guard = null;

    /**
     * If the user may or may not be verified on login.
     *
     * @var string|null
     */
    protected ?string $userVerification = null;

    /**
     * Validate the class instance.
     *
     * @return void
     */
    public function validateResolved(): void
    {
        //
    }

    /**
     * Return or make a new Assertion Creation.
     *
     * @return \Laragear\WebAuthn\Assertion\Creator\AssertionCreation
     */
    protected function assertion(): AssertionCreation
    {
        return $this->assertion ??= new AssertionCreation($this);
    }

    /**
     * Sets the WebAuthn-compatible guard to use.
     *
     * @param  string  $guard
     * @return $this
     */
    public function guard(string $guard): static
    {
        $this->guard = $guard;

        return $this;
    }

    /**
     * Makes the authenticator to only check for user presence on login.
     *
     * @return $this
     */
    public function fastLogin(): static
    {
        $this->assertion()->userVerification = WebAuthn::USER_VERIFICATION_DISCOURAGED;

        return $this;
    }

    /**
     * Makes the authenticator to always verify the user thoroughly on login.
     *
     * @return $this
     */
    public function secureLogin(): static
    {
        $this->assertion()->userVerification = WebAuthn::USER_VERIFICATION_REQUIRED;

        return $this;
    }

    /**
     * Creates an assertion challenge for a user if found.
     *
     * @param  \Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable|string|int|array|null  $credentials
     * @return \Illuminate\Contracts\Support\Responsable
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function toVerify(WebAuthnAuthenticatable|string|int|array|null $credentials = []): Responsable
    {
        $this->assertion()->user = $this->findUser($credentials);

        return $this->container
            ->make(AssertionCreator::class)
            ->send($this->assertion)
            ->then(static function (AssertionCreation $creation): Responsable {
                return $creation->json;
            });
    }

    /**
     * Try to find a user to create an assertion procedure.
     *
     * @param  \Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable|array|int|string|null  $credentials
     * @return \Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable|null
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function findUser(WebAuthnAuthenticatable|array|int|string|null $credentials): ?WebAuthnAuthenticatable
    {
        if ($credentials === null) {
            return null;
        }

        if ($credentials instanceof WebAuthnAuthenticatable) {
            return $credentials;
        }

        // If the developer is using a string or integer, we will understand its trying to
        // retrieve by its ID, otherwise we will fall back to credentials. Once done, we
        // will check it uses WebAuthn if is not null, otherwise we'll fail miserably.
        $user = is_string($credentials) || is_int($credentials)
            // @phpstan-ignore-next-line
            ? Auth::guard($this->guard)->getProvider()->retrieveById($credentials)
            // @phpstan-ignore-next-line
            : Auth::guard($this->guard)->getProvider()->retrieveByCredentials($credentials);

        if ($user && ! $user instanceof WebAuthnAuthenticatable) {
            $guard = $this->guard ?? $this->container->make('config')->get('auth.defaults.guard');

            throw new InvalidArgumentException(
                "The user found for the [$guard] auth guard is not an instance of [WebAuthnAuthenticatable]."
            );
        }

        return $user;
    }
}

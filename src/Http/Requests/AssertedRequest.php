<?php

namespace Laragear\WebAuthn\Http\Requests;

use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Arr;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use UnexpectedValueException;

use function auth;
use function config;
use function method_exists;

class AssertedRequest extends FormRequest
{
    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, string>
     */
    public function rules(): array
    {
        return [
            'id' => 'required|string',
            'rawId' => 'required|string',
            'response.authenticatorData' => 'required|string',
            'response.clientDataJSON' => 'required|string',
            'response.signature' => 'required|string',
            'response.userHandle' => 'sometimes|nullable',
            'type' => 'required|string',
        ];
    }

    /**
     * Check if the login request wants to remember the user as stateful.
     */
    public function hasRemember(): bool
    {
        return $this->hasHeader('X-WebAuthn-Remember')
            || $this->hasHeader('WebAuthn-Remember')
            || $this->filled('remember');
    }

    /**
     * Logs in the user for this assertion request.
     *
     * @param  (\Closure(\Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable):bool)[]  $callbacks
     */
    public function login(
        ?string $guard = null,
        ?bool $remember = null,
        bool $destroySession = false,
        callable|array|null $callbacks = null,
    ): ?WebAuthnAuthenticatable {
        /** @var \Illuminate\Contracts\Auth\StatefulGuard $auth */
        $auth = auth()->guard($guard);

        $remember ??= $this->hasRemember();

        // If the developer is using a callback or an array of callbacks, we will try to use
        // the "attemptWhen" method of the Session Guard. Since these callback are expected
        // to run, we will fail miserably if the guard does not support attempt callbacks.
        if ($callbacks = Arr::wrap($callbacks)) {
            return $this->userWithCallbacks($auth, $callbacks, $remember, $destroySession);
        }

        if ($auth->attempt($this->validated(), $remember)) {
            $this->session()->regenerate($destroySession);

            return $auth->user(); // @phpstan-ignore-line
        }

        return null;
    }

    /**
     * Authenticate the user using the given callbacks.
     *
     * @param  (\Closure(\Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable):bool)[]  $callbacks
     */
    protected function userWithCallbacks(
        StatefulGuard $guard,
        array $callbacks,
        bool $remember,
        bool $destroySession,
    ): ?WebAuthnAuthenticatable {
        if (! method_exists($guard, 'attemptWhen')) {
            $name = config('auth.defaults.guard');
            throw new UnexpectedValueException("The [$name] guard does not support attempt callbacks.");
        }

        if ($guard->attemptWhen($this->validated(), $callbacks, $remember)) {
            $this->session()->regenerate($destroySession);

            return $guard->user(); // @phpstan-ignore-line
        }

        return null;
    }
}

<?php

namespace Laragear\WebAuthn\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;

use function auth;

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
     * @param  string|null  $guard
     *
     * @phpstan-ignore-next-line
     *
     * @return \Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable|\Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function login(
        string $guard = null,
        bool $remember = null,
        bool $destroySession = false
    ): ?WebAuthnAuthenticatable {
        /** @var \Illuminate\Contracts\Auth\StatefulGuard $auth */
        $auth = auth()->guard($guard);

        if ($auth->attempt($this->validated(), $remember ?? $this->hasRemember())) {
            $this->session()->regenerate($destroySession);

            // @phpstan-ignore-next-line
            return $auth->user();
        }

        return null;
    }
}

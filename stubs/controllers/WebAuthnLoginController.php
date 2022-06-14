<?php

namespace App\Http\Controllers\WebAuthn;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Response;
use Laragear\WebAuthn\Http\Requests\AssertedRequest;
use Laragear\WebAuthn\Http\Requests\AssertionRequest;
use function response;

class WebAuthnLoginController
{
    /**
     * Returns the challenge to assertion.
     *
     * @param  \Laragear\WebAuthn\Http\Requests\AssertionRequest  $request
     * @return \Illuminate\Contracts\Support\Responsable
     */
    public function options(AssertionRequest $request): Responsable
    {
        return $request->toVerify($request->validate(['email' => 'sometimes|email|string']));
    }

    /**
     * Log the user in.
     *
     * @param  \Laragear\WebAuthn\Http\Requests\AssertedRequest  $request
     * @return \Illuminate\Http\Response
     */
    public function login(AssertedRequest $request): Response
    {
        return response()->noContent($request->login() ? 204 : 422);
    }
}

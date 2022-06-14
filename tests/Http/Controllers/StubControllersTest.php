<?php

namespace Tests\Http\Controllers;

use Laragear\WebAuthn\Http\Requests\AssertedRequest;
use Laragear\WebAuthn\Http\Requests\AssertionRequest;
use Laragear\WebAuthn\Http\Requests\AttestationRequest;
use Laragear\WebAuthn\Http\Requests\AttestedRequest;
use Laragear\WebAuthn\JsonTransport;
use Tests\Stubs\WebAuthnAuthenticatableUser;
use Tests\TestCase;

class StubControllersTest extends TestCase
{
    protected function defineWebRoutes($router): void
    {
        $router->group([], __DIR__ . '/../../../routes/webauthn.php');
    }

    public function test_uses_attestation_request(): void
    {
        $request = $this->mock(AttestationRequest::class);

        $request->expects('fastRegistration')->andReturnSelf();
        $request->expects('toCreate')->andReturn(new JsonTransport());

        $this->postJson('webauthn/register/options')->assertOk();
    }

    public function test_uses_attested_request(): void
    {
        $this->mock(AttestedRequest::class)->expects('save')->andReturn();

        $this->postJson('webauthn/register')->assertNoContent();
    }

    public function test_uses_assertion_request(): void
    {
        $request = $this->mock(AssertionRequest::class);

        $request->expects('validate')
            ->with(['email' => 'sometimes|email|string'])
            ->andReturn(['email' => 'email@email.com']);

        $request->expects('toVerify')
            ->with(['email' => 'email@email.com'])
            ->andReturn(new JsonTransport());

        $this->postJson('webauthn/login/options')->assertOk();
    }

    public function test_uses_asserted_request(): void
    {
        $this->mock(AssertedRequest::class)->expects('login')->andReturn(new WebAuthnAuthenticatableUser());

        $this->postJson('webauthn/login')->assertNoContent();
    }

    public function test_uses_asserted_request_and_fails_login_with_422(): void
    {
        $this->mock(AssertedRequest::class)->expects('login')->andReturnNull();

        $this->postJson('webauthn/login')->assertStatus(422);
    }
}

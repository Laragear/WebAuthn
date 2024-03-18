<?php

namespace Tests\Http\Requests;

use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Laragear\WebAuthn\ByteBuffer;
use Laragear\WebAuthn\Challenge;
use Laragear\WebAuthn\Events\CredentialCreated;
use Laragear\WebAuthn\Http\Requests\AttestedRequest;
use Laragear\WebAuthn\Models\WebAuthnCredential;
use Orchestra\Testbench\Attributes\WithMigration;
use Tests\DatabaseTestCase;
use Tests\FakeAuthenticator;
use Tests\Stubs\WebAuthnAuthenticatableUser;

use function base64_decode;
use function config;

#[WithMigration]
class AttestedRequestTest extends DatabaseTestCase
{
    protected function defineDatabaseSeeders(): void
    {
        $this->be(
            WebAuthnAuthenticatableUser::forceCreate([
                'name' => FakeAuthenticator::ATTESTATION_USER['displayName'],
                'email' => FakeAuthenticator::ATTESTATION_USER['name'],
                'password' => 'test_password',
            ])
        );
    }

    protected function defineWebRoutes($router): void
    {
        $router->post('test', static function (AttestedRequest $request): void {
            $request->save();
        });
    }

    public function test_forbidden_if_user_not_authenticated(): void
    {
        Auth::logout();

        $this->postJson('test')->assertForbidden();
    }

    public function test_forbidden_if_user_not_webauthn_authenticatable(): void
    {
        $this->be(new User());

        $this->postJson('test')->assertForbidden();
    }

    public function test_invalid_if_web_authn_response_not_structured(): void
    {
        $this->postJson('test', [
            'id' => 'test',
            'rawId' => 'test',
            'response' => [
                'clientDataJSON' => 'test',
            ],
            'type' => 'test',
        ])->assertJsonValidationErrorFor('response.attestationObject');
    }

    public function test_calls_validator_if_valid_and_authorized(): void
    {
        $this->session(['_webauthn' => new Challenge(
            new ByteBuffer(
                base64_decode(FakeAuthenticator::ATTESTATION_CHALLENGE)),
            60,
            false,
            ['user_uuid' => FakeAuthenticator::ATTESTATION_USER['id']]
        ),
        ]);

        $event = Event::fake(CredentialCreated::class);

        $this->postJson('test', FakeAuthenticator::attestationResponse())->assertOk();

        $event->assertDispatched(CredentialCreated::class, function (CredentialCreated $event): bool {
            return FakeAuthenticator::CREDENTIAL_ID === $event->credential->getKey();
        });

        $this->assertDatabaseHas(WebAuthnCredential::class, [
            'id' => FakeAuthenticator::CREDENTIAL_ID,
            'authenticatable_type' => WebAuthnAuthenticatableUser::class,
            'authenticatable_id' => 1,
        ]);
    }

    public function test_uses_custom_session_key(): void
    {
        config(['webauthn.challenge.key' => 'foo']);

        $this->session(['foo' => new Challenge(
            new ByteBuffer(
                base64_decode(FakeAuthenticator::ATTESTATION_CHALLENGE)),
            60,
            false,
            ['user_uuid' => FakeAuthenticator::ATTESTATION_USER['id']]
        ),
        ]);

        $this->postJson('test', FakeAuthenticator::attestationResponse())->assertOk();
    }

    public function test_saves_with_array(): void
    {
        Route::middleware('web')->post('test', static function (AttestedRequest $request): void {
            $request->save(['alias' => 'foo']);
        });

        $this->session(['_webauthn' => new Challenge(
            new ByteBuffer(
                base64_decode(FakeAuthenticator::ATTESTATION_CHALLENGE)),
            60,
            false,
            ['user_uuid' => FakeAuthenticator::ATTESTATION_USER['id']]
        ),
        ]);

        $this->postJson('test', FakeAuthenticator::attestationResponse())->assertOk();

        $this->assertDatabaseHas(WebAuthnCredential::class, [
            'id' => FakeAuthenticator::CREDENTIAL_ID,
            'authenticatable_type' => WebAuthnAuthenticatableUser::class,
            'authenticatable_id' => 1,
            'alias' => 'foo',
        ]);
    }

    public function test_saves_with_callable(): void
    {
        Route::middleware('web')->post('test', static function (AttestedRequest $request): void {
            $request->save(function ($credential) {
                $credential->alias = 'foo';
            });
        });

        $this->session(['_webauthn' => new Challenge(
            new ByteBuffer(base64_decode(FakeAuthenticator::ATTESTATION_CHALLENGE)),
            60,
            false,
            ['user_uuid' => FakeAuthenticator::ATTESTATION_USER['id']]
        ),
        ]);

        $this->postJson('test', FakeAuthenticator::attestationResponse())->assertOk();

        $this->assertDatabaseHas(WebAuthnCredential::class, [
            'id' => FakeAuthenticator::CREDENTIAL_ID,
            'authenticatable_type' => WebAuthnAuthenticatableUser::class,
            'authenticatable_id' => 1,
            'alias' => 'foo',
        ]);
    }

    public function test_saves_return_credential_key(): void
    {
        $this->session(['_webauthn' => new Challenge(
            new ByteBuffer(base64_decode(FakeAuthenticator::ATTESTATION_CHALLENGE)),
            60,
            false,
            ['user_uuid' => FakeAuthenticator::ATTESTATION_USER['id']]
        ),
        ]);

        Route::middleware('web')->post('test', static function (AttestedRequest $request): array {
            return [$request->save()];
        });

        $this->postJson('test', FakeAuthenticator::attestationResponse())
            ->assertJson([FakeAuthenticator::CREDENTIAL_ID]);
    }
}

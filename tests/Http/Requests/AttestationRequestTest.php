<?php

namespace Tests\Http\Requests;

use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Laragear\WebAuthn\Challenge;
use Laragear\WebAuthn\Http\Requests\AttestationRequest;
use Laragear\WebAuthn\Models\WebAuthnCredential;
use Ramsey\Uuid\Uuid;
use Tests\DatabaseTestCase;
use Tests\FakeAuthenticator;
use Tests\Stubs\WebAuthnAuthenticatableUser;

use function config;

class AttestationRequestTest extends DatabaseTestCase
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

    public function test_forbidden_if_user_not_authenticated(): void
    {
        Auth::logout();

        Route::middleware('web')->post('test', function (AttestationRequest $request) {
            return $request->toCreate();
        });

        $this->postJson('test')->assertForbidden();
    }

    public function test_forbidden_if_user_not_webauthn_authenticatable(): void
    {
        $this->be(new User());

        Route::middleware('web')->post('test', function (AttestationRequest $request) {
            return $request->toCreate();
        });

        $this->postJson('test')->assertForbidden();
    }

    public function test_returns_response_and_saves_challenge(): void
    {
        Route::middleware('web')->post('test', function (AttestationRequest $request) {
            return $request->toCreate();
        });

        $this->postJson('test')
            ->assertSessionHas('_webauthn', static function (Challenge $challenge): bool {
                static::assertFalse($challenge->verify);

                return true;
            });
    }

    public function test_uses_custom_session_key(): void
    {
        config(['webauthn.challenge.key' => 'foo']);

        Route::middleware('web')->post('test', function (AttestationRequest $request) {
            return $request->toCreate();
        });

        $this->postJson('test')->assertSessionHas('foo');
    }

    public function test_uses_fast_registration(): void
    {
        Route::middleware('web')->post('test', function (AttestationRequest $request) {
            return $request->fastRegistration()->toCreate();
        });

        $this->postJson('test')
            ->assertSessionHas('_webauthn', static function (Challenge $challenge): bool {
                static::assertFalse($challenge->verify);

                return true;
            })
            ->assertJsonPath('authenticatorSelection.userVerification', 'discouraged');
    }

    public function test_uses_secure_registration(): void
    {
        Route::middleware('web')->post('test', function (AttestationRequest $request) {
            return $request->secureRegistration()->toCreate();
        });

        $this->postJson('test')
            ->assertSessionHas('_webauthn', static function (Challenge $challenge): bool {
                static::assertTrue($challenge->verify);

                return true;
            })
            ->assertJsonPath('authenticatorSelection.userVerification', 'required');
    }

    public function test_uses_userless_and_verifies_user(): void
    {
        Route::middleware('web')->post('test', function (AttestationRequest $request) {
            return $request->userless()->toCreate();
        });

        $this->postJson('test')
            ->assertSessionHas('_webauthn', static function (Challenge $challenge): bool {
                static::assertTrue($challenge->verify);

                return true;
            })
            ->assertJsonFragment([
                'authenticatorSelection' => [
                    'residentKey' => 'required',
                    'requireResidentKey' => true,
                    'userVerification' => 'required',
                ],
            ]);
    }

    public function test_allows_duplicates(): void
    {
        Route::middleware('web')->post('test', function (AttestationRequest $request) {
            return $request->allowDuplicates()->toCreate();
        });

        WebAuthnCredential::forceCreate([
            'id' => 'test_id',
            'authenticatable_type' => WebAuthnAuthenticatableUser::class,
            'authenticatable_id' => 1,
            'user_id' => 'e8af6f703f8042aa91c30cf72289aa07',
            'counter' => 0,
            'rp_id' => 'localhost',
            'origin' => 'http://localhost',
            'aaguid' => Uuid::NIL,
            'attestation_format' => 'none',
            'public_key' => 'test_key',
        ]);

        $this->postJson('test')->assertJsonMissing(['excludeCredentials']);
    }
}

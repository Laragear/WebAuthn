<?php

namespace Tests\Assertion;

use Illuminate\Http\Request;
use Illuminate\Testing\TestResponse;
use Laragear\WebAuthn\Assertion\Creator\AssertionCreation;
use Laragear\WebAuthn\Assertion\Creator\AssertionCreator;
use Laragear\WebAuthn\Challenge;
use Laragear\WebAuthn\Enums\UserVerification;
use Ramsey\Uuid\Uuid;
use Tests\DatabaseTestCase;
use Tests\Stubs\WebAuthnAuthenticatableUser;

use function config;
use function in_array;
use function now;
use function session;

class CreatorTest extends DatabaseTestCase
{
    protected WebAuthnAuthenticatableUser $user;
    protected AssertionCreation $creation;
    protected AssertionCreator $creator;

    protected function defineDatabaseSeeders(): void
    {
        $this->user = WebAuthnAuthenticatableUser::forceCreate([
            'name' => 'test',
            'email' => 'test@email.com',
            'password' => 'test_password',
        ]);
    }

    protected function setUp(): void
    {
        $this->afterApplicationCreated(function (): void {
            $this->creator = new AssertionCreator($this->app);
            $this->creation = new AssertionCreation();

            $this->startSession();
        });

        parent::setUp();
    }

    protected function response(): TestResponse
    {
        return $this->createTestResponse(
            $this->creator->send($this->creation)->thenReturn()->json->toResponse(new Request), null
        );
    }

    public function test_uses_config_timeout(): void
    {
        config(['webauthn.challenge.timeout' => 120]);

        $this->travelTo(now()->startOfSecond());

        $this->response()
            ->assertSessionHas('_webauthn', static function (Challenge $challenge): bool {
                return now()->addMinutes(2)->getTimestamp() === $challenge->expiresAt
                    && 120 === $challenge->timeout;
            })
            ->assertJson([
                'timeout' => 120000,
                'challenge' => session('_webauthn')->data->toBase64Url(),
            ]);
    }

    public function test_response_defaults_without_credentials(): void
    {
        $this->user->webAuthnCredentials()->make()->forceFill([
            'id' => 'test_id',
            'user_id' => Uuid::NIL,
            'counter' => 0,
            'rp_id' => 'localhost',
            'origin' => 'http://localhost:8000',
            'aaguid' => Uuid::NIL,
            'public_key' => 'test_key',
            'attestation_format' => 'none',
        ]);

        $this->response()
            ->assertSessionHas('_webauthn', function (Challenge $challenge): bool {
                static::assertSame(60, $challenge->timeout);
                static::assertSame(now()->addMinute()->getTimestamp(), $challenge->expiresAt);
                static::assertFalse($challenge->verify);

                return true;
            })
            ->assertJson([
                'timeout' => 60000,
                'challenge' => session('_webauthn')->data->toBase64Url(),
            ]);
    }

    public function test_response_doesnt_add_credentials_if_user_has_no_credentials(): void
    {
        $this->creation->user = $this->user;

        $this->response()
            ->assertJson([
                'timeout' => 60000,
                'challenge' => session('_webauthn')->data->toBase64Url(),
            ]);
    }

    public function test_response_adds_accepted_credentials_if_there_is_credentials(): void
    {
        $this->creation->user = $this->user;

        $this->user->webAuthnCredentials()->make()->forceFill([
            'id' => 'test_id',
            'user_id' => Uuid::NIL,
            'counter' => 0,
            'rp_id' => 'localhost',
            'origin' => 'http://localhost:8000',
            'aaguid' => Uuid::NIL,
            'public_key' => 'test_key',
            'attestation_format' => 'none',
        ])->save();

        $this->response()
            ->assertJson([
                'timeout' => 60000,
                'challenge' => session('_webauthn')->data->toBase64Url(),
                'allowCredentials' => [
                    ['id' => 'test_id', 'type' => 'public-key'],
                ],
            ]);
    }

    public function test_response_doesnt_add_credentials_blacklisted(): void
    {
        $this->creation->user = $this->user;

        $this->user->webAuthnCredentials()->make()->forceFill([
            'id' => 'test_id',
            'user_id' => Uuid::NIL,
            'counter' => 0,
            'rp_id' => 'localhost',
            'origin' => 'http://localhost:8000',
            'aaguid' => Uuid::NIL,
            'public_key' => 'test_key',
            'attestation_format' => 'none',
            'disabled_at' => now(),
        ])->save();

        $this->response()
            ->assertJson([
                'timeout' => 60000,
                'challenge' => session('_webauthn')->data->toBase64Url(),
            ]);
    }

    public function test_forces_user_verification(): void
    {
        $this->creation->userVerification = UserVerification::REQUIRED;

        $this->response()
            ->assertSessionHas('_webauthn', function (Challenge $challenge): bool {
                return $challenge->verify;
            })
            ->assertJson([
                'timeout' => 60000,
                'challenge' => session('_webauthn')->data->toBase64Url(),
                'userVerification' => UserVerification::REQUIRED->value,
            ]);
    }

    public function test_challenge_includes_accepted_credentials(): void
    {
        $this->creation->user = $this->user;

        $this->user->webAuthnCredentials()->make()->forceFill([
            'id' => 'test_id',
            'user_id' => Uuid::NIL,
            'counter' => 0,
            'rp_id' => 'localhost',
            'origin' => 'http://localhost:8000',
            'aaguid' => Uuid::NIL,
            'public_key' => 'test_key',
            'attestation_format' => 'none',
        ])->save();

        $this->response()
            ->assertSessionHas('_webauthn', function (Challenge $challenge): bool {
                return in_array('test_id', $challenge->properties['credentials'], true);
            });
    }
}

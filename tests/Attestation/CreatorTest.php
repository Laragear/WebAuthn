<?php

namespace Tests\Attestation;

use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreation;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreator;
use Laragear\WebAuthn\Challenge;
use Laragear\WebAuthn\Enums\ResidentKey;
use Laragear\WebAuthn\Enums\UserVerification;
use Ramsey\Uuid\Uuid;
use Tests\DatabaseTestCase;
use Tests\Stubs\WebAuthnAuthenticatableUser;
use function config;
use function now;
use function session;

class CreatorTest extends DatabaseTestCase
{
    protected WebAuthnAuthenticatableUser $user;
    protected AttestationCreation $creation;
    protected AttestationCreator $creator;

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
            $this->creator = new AttestationCreator($this->app);
            $this->creation = new AttestationCreation($this->user);

            $this->startSession();
        });

        parent::setUp();
    }

    protected function response(): TestResponse
    {
        return $this->createTestResponse(
            $this->creator->send($this->creation)->thenReturn()->json->toResponse(new Request()), null
        );
    }

    public function test_base_structure(): void
    {
        $this->travelTo(now()->startOfSecond());

        $this->response()
            ->assertSessionHas('_webauthn', function (Challenge $challenge): bool {
                static::assertSame(60, $challenge->timeout);
                static::assertSame(now()->addMinute()->getTimestamp(), $challenge->expiresAt);
                static::assertTrue(Uuid::isValid(Uuid::fromString($challenge->properties['user_uuid'])));
                static::assertSame('test@email.com', $challenge->properties['user_handle']);
                static::assertFalse($challenge->verify);

                return true;
            })
            ->assertJson([
                'rp' => [
                    'name' => 'Laravel',
                ],
                'user' => [
                    'name' => 'test@email.com',
                    'displayName' => 'test',
                    'id' => session('_webauthn')->properties['user_uuid'],
                ],
                'pubKeyCredParams' => [
                    ['type' => 'public-key', 'alg' => -7],
                    ['type' => 'public-key', 'alg' => -257],
                ],
                'attestation' => 'none',
                'timeout' => 60000,
                'challenge' => session('_webauthn')->data->toBase64Url(),
            ]);
    }

    public function test_uses_relying_party_config(): void
    {
        config(['webauthn.relying_party' => [
            'id' => 'https://foo.bar',
            'name' => 'foo',
        ]]);

        $this->response()->assertJsonFragment([
            'rp' => [
                'id' => 'https://foo.bar',
                'name' => 'foo',
            ],
        ]);
    }

    public function test_asks_for_user_verification(): void
    {
        $this->creation->userVerification = UserVerification::REQUIRED;

        $this->response()
            ->assertSessionHas('_webauthn', static function (Challenge $challenge): bool {
                return $challenge->verify;
            })
            ->assertJsonFragment([
                'authenticatorSelection' => [
                    'userVerification' => 'required',
                ],
            ]);
    }

    public function test_asks_for_user_presence(): void
    {
        $this->creation->userVerification = UserVerification::DISCOURAGED;

        $this->response()
            ->assertSessionHas('_webauthn', static function (Challenge $challenge): bool {
                return ! $challenge->verify;
            })
            ->assertJsonFragment([
                'authenticatorSelection' => [
                    'userVerification' => 'discouraged',
                ],
            ]);
    }

    public function test_asks_for_resident_key(): void
    {
        $this->creation->residentKey = ResidentKey::REQUIRED;

        $this->response()
            ->assertSessionHas('_webauthn', static function (Challenge $challenge): bool {
                return $challenge->verify;
            })
            ->assertJsonFragment([
                'authenticatorSelection' => [
                    'residentKey' => 'required',
                    'requireResidentKey' => true,
                    'userVerification' => 'required',
                ],
            ]);
    }

    public function test_user_reuses_uuid_from_other_credential(): void
    {
        $this->user->webAuthnCredentials()->make()->forceFill([
            'id' => 'test_id',
            'user_id' => $uuid = Str::uuid(),
            'rp_id' => 'test',
            'origin' => 'test',
            'public_key' => 'test',
        ])->save();

        $this->response()
            ->assertJsonPath('user.id', $uuid->toString());
    }

    public function test_adds_existing_credentials_if_unique_by_default(): void
    {
        $this->user->webAuthnCredentials()->make()->forceFill([
            'id' => 'test_id',
            'user_id' => Str::uuid(),
            'rp_id' => 'test',
            'origin' => 'test',
            'public_key' => 'test',
        ])->save();

        $this->response()
            ->assertJsonFragment([
                'excludeCredentials' => [
                    ['id' => 'test_id', 'type' => 'public-key'],
                ],
            ]);
    }

    public function test_doesnt_adds_credentials_if_allows_duplicates(): void
    {
        $this->creation->uniqueCredentials = false;

        $this->user->webAuthnCredentials()->make()->forceFill([
            'id' => 'test_id',
            'user_id' => Str::uuid(),
            'rp_id' => 'test',
            'origin' => 'test',
            'public_key' => 'test',
        ])->save();

        $this->response()->assertJsonMissing(['excludeCredentials']);
    }
}

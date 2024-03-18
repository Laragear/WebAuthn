<?php

namespace Tests;

use Illuminate\Support\Carbon;
use Laragear\WebAuthn\Models\WebAuthnCredential;
use Ramsey\Uuid\Uuid;
use function now;

class WebAuthnAuthenticationTest extends DatabaseTestCase
{
    protected Stubs\WebAuthnAuthenticatableUser $user;

    protected function defineDatabaseSeeders(): void
    {
        $this->user = Stubs\WebAuthnAuthenticatableUser::forceCreate([
            'name' => FakeAuthenticator::ATTESTATION_USER['displayName'],
            'email' => FakeAuthenticator::ATTESTATION_USER['name'],
            'password' => 'test_password',
        ]);

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
    }

    public function test_shows_webauthn_data(): void
    {
        static::assertSame([
            'name' => FakeAuthenticator::ATTESTATION_USER['name'],
            'displayName' => FakeAuthenticator::ATTESTATION_USER['displayName'],
        ], $this->user->webAuthnData());
    }

    public function test_flushes_all_credentials(): void
    {
        $this->user->webAuthnCredentials()->make()->forceFill([
            'id' => 'test_id_2',
            'user_id' => Uuid::NIL,
            'counter' => 10,
            'rp_id' => 'localhost',
            'origin' => 'http://localhost:8000',
            'aaguid' => Uuid::NIL,
            'public_key' => 'test_key',
            'attestation_format' => 'none',
            'disabled_at' => now(),
        ])->save();

        $this->user->flushCredentials();

        $this->assertDatabaseCount(WebAuthnCredential::class, 0);
    }

    public function test_flushes_all_credentials_using_loaded_relation(): void
    {
        $this->user->webAuthnCredentials()->make()->forceFill([
            'id' => 'test_id_2',
            'user_id' => Uuid::NIL,
            'counter' => 10,
            'rp_id' => 'localhost',
            'origin' => 'http://localhost:8000',
            'aaguid' => Uuid::NIL,
            'public_key' => 'test_key',
            'attestation_format' => 'none',
            'disabled_at' => now(),
        ])->save();

        $this->user->load('webAuthnCredentials');

        static::assertCount(2, $this->user->webAuthnCredentials);

        $this->user->flushCredentials();

        static::assertEmpty($this->user->webAuthnCredentials);

        $this->assertDatabaseCount(WebAuthnCredential::class, 0);
    }

    public function test_flushes_all_credentials_except_given_id(): void
    {
        $this->user->webAuthnCredentials()->make()->forceFill([
            'id' => 'test_id_2',
            'user_id' => Uuid::NIL,
            'counter' => 10,
            'rp_id' => 'localhost',
            'origin' => 'http://localhost:8000',
            'aaguid' => Uuid::NIL,
            'public_key' => 'test_key',
            'attestation_format' => 'none',
            'disabled_at' => now(),
        ])->save();

        $this->user->flushCredentials('test_id_2');

        $this->assertDatabaseCount(WebAuthnCredential::class, 1);
        $this->assertDatabaseMissing(WebAuthnCredential::class, [
            'id' => 'test_id',
        ]);
    }

    public function test_flushes_all_credentials_using_loaded_relation_except_given_id(): void
    {
        $this->user->webAuthnCredentials()->make()->forceFill([
            'id' => 'test_id_2',
            'user_id' => Uuid::NIL,
            'counter' => 10,
            'rp_id' => 'localhost',
            'origin' => 'http://localhost:8000',
            'aaguid' => Uuid::NIL,
            'public_key' => 'test_key',
            'attestation_format' => 'none',
            'disabled_at' => now(),
        ])->save();

        $this->user->load('webAuthnCredentials');

        static::assertCount(2, $this->user->webAuthnCredentials);

        $this->user->flushCredentials('test_id_2');

        static::assertCount(1, $this->user->webAuthnCredentials);
        static::assertTrue($this->user->webAuthnCredentials->contains('id', 'test_id_2'));

        $this->assertDatabaseCount(WebAuthnCredential::class, 1);
        $this->assertDatabaseMissing(WebAuthnCredential::class, [
            'id' => 'test_id',
        ]);
    }

    public function test_disables_all_credentials(): void
    {
        $this->travelTo(Carbon::now()->startOfSecond());

        $this->user->webAuthnCredentials()->make()->forceFill([
            'id' => 'test_id_2',
            'user_id' => Uuid::NIL,
            'counter' => 10,
            'rp_id' => 'localhost',
            'origin' => 'http://localhost:8000',
            'aaguid' => Uuid::NIL,
            'public_key' => 'test_key',
            'attestation_format' => 'none',
            'disabled_at' => now()->subMinute(),
        ])->save();

        $this->user->disableAllCredentials();

        $this->assertDatabaseCount(WebAuthnCredential::class, 2);
        $this->assertDatabaseHas(WebAuthnCredential::class, [
            'id' => 'test_id',
            'disabled_at' => now()->toDateTimeString(),
        ]);
        $this->assertDatabaseHas(WebAuthnCredential::class, [
            'id' => 'test_id_2',
            'disabled_at' => now()->subMinute()->toDateTimeString(),
        ]);
    }

    public function test_disables_all_credentials_with_loaded_relation(): void
    {
        $this->travelTo(Carbon::now()->startOfSecond());

        $this->user->webAuthnCredentials()->make()->forceFill([
            'id' => 'test_id_2',
            'user_id' => Uuid::NIL,
            'counter' => 10,
            'rp_id' => 'localhost',
            'origin' => 'http://localhost:8000',
            'aaguid' => Uuid::NIL,
            'public_key' => 'test_key',
            'attestation_format' => 'none',
            'disabled_at' => now()->subMinute(),
        ])->save();

        $this->user->load('webAuthnCredentials');

        $this->user->disableAllCredentials();

        static::assertTrue($this->user->webAuthnCredentials->firstWhere('id', 'test_id')->isDisabled());
        static::assertTrue($this->user->webAuthnCredentials->firstWhere('id', 'test_id_2')->isDisabled());

        $this->assertDatabaseCount(WebAuthnCredential::class, 2);
        $this->assertDatabaseHas(WebAuthnCredential::class, [
            'id' => 'test_id',
            'disabled_at' => now()->toDateTimeString(),
        ]);
        $this->assertDatabaseHas(WebAuthnCredential::class, [
            'id' => 'test_id_2',
            'disabled_at' => now()->subMinute()->toDateTimeString(),
        ]);
    }

    public function test_disables_all_credentials_except_one(): void
    {
        $this->travelTo(Carbon::now()->startOfSecond());

        $this->user->webAuthnCredentials()->make()->forceFill([
            'id' => 'test_id_2',
            'user_id' => Uuid::NIL,
            'counter' => 10,
            'rp_id' => 'localhost',
            'origin' => 'http://localhost:8000',
            'aaguid' => Uuid::NIL,
            'public_key' => 'test_key',
            'attestation_format' => 'none',
        ])->save();

        $this->user->disableAllCredentials('test_id');

        $this->assertDatabaseCount(WebAuthnCredential::class, 2);
        $this->assertDatabaseHas(WebAuthnCredential::class, [
            'id' => 'test_id',
            'disabled_at' => null,
        ]);
        $this->assertDatabaseHas(WebAuthnCredential::class, [
            'id' => 'test_id_2',
            'disabled_at' => now()->toDateTimeString(),
        ]);
    }

    public function test_disables_all_credentials_with_loaded_relation_except_one(): void
    {
        $this->travelTo(Carbon::now()->startOfSecond());

        $this->user->webAuthnCredentials()->make()->forceFill([
            'id' => 'test_id_2',
            'user_id' => Uuid::NIL,
            'counter' => 10,
            'rp_id' => 'localhost',
            'origin' => 'http://localhost:8000',
            'aaguid' => Uuid::NIL,
            'public_key' => 'test_key',
            'attestation_format' => 'none',
        ])->save();

        $this->user->load('webAuthnCredentials');

        $this->user->disableAllCredentials('test_id_2');

        static::assertTrue($this->user->webAuthnCredentials->firstWhere('id', 'test_id')->isDisabled());
        static::assertFalse($this->user->webAuthnCredentials->firstWhere('id', 'test_id_2')->isDisabled());

        $this->assertDatabaseCount(WebAuthnCredential::class, 2);
        $this->assertDatabaseHas(WebAuthnCredential::class, [
            'id' => 'test_id',
            'disabled_at' => now()->toDateTimeString(),
        ]);
        $this->assertDatabaseHas(WebAuthnCredential::class, [
            'id' => 'test_id_2',
            'disabled_at' => null,
        ]);
    }
}

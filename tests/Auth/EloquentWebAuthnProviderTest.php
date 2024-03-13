<?php

/** @noinspection JsonEncodingApiUsageInspection */

namespace Tests\Auth;

use Illuminate\Support\Facades\Auth;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidator;
use Laragear\WebAuthn\Exceptions\AssertionException;
use Laragear\WebAuthn\Models\WebAuthnCredential;
use Mockery;
use Orchestra\Testbench\Attributes\WithMigration;
use Psr\Log\LoggerInterface;
use Ramsey\Uuid\Uuid;
use Tests\FakeAuthenticator;
use Tests\Stubs\WebAuthnAuthenticatableUser;
use Tests\TestCase;

#[WithMigration]
class EloquentWebAuthnProviderTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        $app->make('config')->set('auth.providers.users.driver', 'eloquent-webauthn');
        $app->make('config')->set('auth.providers.users.model', WebAuthnAuthenticatableUser::class);
    }

    protected function afterRefreshingDatabase(): void
    {
        WebAuthnAuthenticatableUser::forceCreate([
            'name' => FakeAuthenticator::ATTESTATION_USER['displayName'],
            'email' => FakeAuthenticator::ATTESTATION_USER['name'],
            'password' => '$2y$10$c/yQW6o.mEiCfys7enU29.4ETjmg/jdw.4puMTWbceEFGijejPkSW', // password
        ]);

        WebAuthnCredential::forceCreate([
            'id' => FakeAuthenticator::CREDENTIAL_ID,
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
    }

    public function test_retrieves_user_using_webauthn(): void
    {
        $provider = Auth::createUserProvider('users');

        $retrieved = $provider->retrieveByCredentials([
            'id' => FakeAuthenticator::CREDENTIAL_ID,
            'rawId' => 'raw',
            'response' => ['something'],
            'type' => 'public-key',
        ]);

        static::assertTrue(WebAuthnAuthenticatableUser::query()->first()->is($retrieved));

        $retrieved = $provider->retrieveByCredentials([
            'id' => '27EdS6eTDHCTa9Y73G9gY1b81yVJuuiu1TTyorFicBf',
            'rawId' => 'raw',
            'response' => ['something'],
            'type' => 'public-key',
        ]);

        static::assertNull($retrieved);
    }

    public function test_retrieves_user_using_credentials(): void
    {
        $provider = Auth::createUserProvider('users');

        $retrieved = $provider->retrieveByCredentials([
            'email' => FakeAuthenticator::ATTESTATION_USER['name'],
        ]);

        static::assertTrue(WebAuthnAuthenticatableUser::query()->first()->is($retrieved));

        $retrieved = $provider->retrieveByCredentials([
            'email' => 'invalid@invalid.com',
        ]);

        static::assertNull($retrieved);
    }

    public function test_retrieves_user_using_classic_credentials_without_fallback(): void
    {
        $this->app->make('config')->set('auth.providers.users.password_fallback', false);

        $this->test_retrieves_user_using_credentials();
    }

    public function test_validates_webauthn(): void
    {
        $this->mock(AssertionValidator::class)
            ->expects('send->thenReturn')
            ->andReturn();

        $valid = Auth::createUserProvider('users')
            ->validateCredentials(WebAuthnAuthenticatableUser::first(), FakeAuthenticator::assertionResponse());

        static::assertTrue($valid);
    }

    public function test_validates_webauthn_to_false(): void
    {
        $this->mock(AssertionValidator::class)
            ->expects('send->thenReturn')
            ->andThrow(AssertionException::make('invalid'));

        $this->instance('log', $logger = Mockery::mock(LoggerInterface::class));

        $logger->expects('debug')
            ->with('Assertion Error: invalid', [])
            ->andReturn();

        $valid = Auth::createUserProvider('users')
            ->validateCredentials(WebAuthnAuthenticatableUser::first(), FakeAuthenticator::assertionResponse());

        static::assertFalse($valid);
    }

    public function test_validates_password(): void
    {
        $valid = Auth::createUserProvider('users')
            ->validateCredentials(WebAuthnAuthenticatableUser::first(), ['password' => 'password']);

        static::assertTrue($valid);
    }

    public function test_validates_password_to_false(): void
    {
        $valid = Auth::createUserProvider('users')
            ->validateCredentials(WebAuthnAuthenticatableUser::first(), ['password' => 'invalid']);

        static::assertFalse($valid);
    }

    public function test_doesnt_validates_password_when_fallback_is_false(): void
    {
        $this->app->make('config')->set('auth.providers.users.password_fallback', false);

        $valid = Auth::createUserProvider('users')
            ->validateCredentials(WebAuthnAuthenticatableUser::first(), ['password' => 'password']);

        static::assertFalse($valid);
    }
}

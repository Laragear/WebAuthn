<?php

/** @noinspection JsonEncodingApiUsageInspection */

namespace Tests\Models;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Laragear\WebAuthn\Events\CredentialDisabled;
use Laragear\WebAuthn\Events\CredentialEnabled;
use Laragear\WebAuthn\Models\WebAuthnCredential;
use Ramsey\Uuid\Uuid;
use Tests\DatabaseTestCase;
use Tests\FakeAuthenticator;
use Tests\Stubs\WebAuthnAuthenticatableUser;
use function array_merge;
use function json_encode;
use function now;

class WebAuthnCredentialTest extends DatabaseTestCase
{
    protected function defineDatabaseSeeders(): void
    {
        WebAuthnAuthenticatableUser::forceCreate([
            'name' => FakeAuthenticator::ATTESTATION_USER['displayName'],
            'email' => FakeAuthenticator::ATTESTATION_USER['name'],
            'password' => 'test_password',
        ]);

        $base = static function (array $override = []): array {
            return array_merge([
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
                'updated_at' => now(),
                'created_at' => now(),
            ], $override);
        };

        DB::table('webauthn_credentials')->insert($base());

        DB::table('webauthn_credentials')->insert($base([
            'id' => '27EdS6eTDHCTa9Y73G9gY1b81yVJuuiu1TTyorFicBf',
        ]));

        DB::table('webauthn_credentials')->insert($base([
            'id' => 'HLs22xpFT7ilSbYvbARFNf9Q3nVyfczTT9LFhtFT89D',
            'disabled_at' => now()->toDateTimeString(),
        ]));
    }

    public function test_queries_enabled_credentials(): void
    {
        static::assertSame(2, WebAuthnCredential::query()->whereEnabled()->count());
    }

    public function test_queries_disabled_credentials(): void
    {
        static::assertSame(1, WebAuthnCredential::query()->whereDisabled()->count());
    }

    public function test_is_enabled(): void
    {
        $credential = WebAuthnCredential::find(FakeAuthenticator::CREDENTIAL_ID);

        static::assertTrue($credential->isEnabled());
        static::assertFalse($credential->isDisabled());
    }

    public function test_is_disabled(): void
    {
        $credential = WebAuthnCredential::find('HLs22xpFT7ilSbYvbARFNf9Q3nVyfczTT9LFhtFT89D');

        static::assertTrue($credential->isDisabled());
        static::assertFalse($credential->isEnabled());
    }

    public function test_disables_credential(): void
    {
        $event = Event::fake();

        $credential = WebAuthnCredential::find(FakeAuthenticator::CREDENTIAL_ID);

        $this->travelTo(now()->startOfSecond());

        $credential->disable();
        $credential->disable();

        $event->assertDispatchedTimes(CredentialDisabled::class);

        $this->assertDatabaseHas(WebAuthnCredential::class, [
            'id' => FakeAuthenticator::CREDENTIAL_ID,
            'disabled_at' => now()->toDateTimeString(),
        ]);
    }

    public function test_enables_credential(): void
    {
        $event = Event::fake();

        $credential = WebAuthnCredential::find('HLs22xpFT7ilSbYvbARFNf9Q3nVyfczTT9LFhtFT89D');

        $this->travelTo(now()->startOfSecond());

        $credential->enable();
        $credential->enable();

        $event->assertDispatchedTimes(CredentialEnabled::class);

        $this->assertDatabaseHas(WebAuthnCredential::class, [
            'id' => FakeAuthenticator::CREDENTIAL_ID,
            'disabled_at' => null,
        ]);
    }

    public function test_syncs_counter(): void
    {
        $credential = WebAuthnCredential::find(FakeAuthenticator::CREDENTIAL_ID);

        $credential->syncCounter(20);

        $this->assertDatabaseHas(WebAuthnCredential::class, [
            'id' => FakeAuthenticator::CREDENTIAL_ID,
            'counter' => 20,
        ]);
    }

    public function test_authenticatable(): void
    {
        $user = WebAuthnCredential::find(FakeAuthenticator::CREDENTIAL_ID)->authenticatable;

        static::assertInstanceOf(WebAuthnAuthenticatableUser::class, $user);
    }

    public function test_shows_serializes_few_columns(): void
    {
        $json = WebAuthnCredential::find(FakeAuthenticator::CREDENTIAL_ID)->toJson();

        static::assertJsonStringEqualsJsonString(
            json_encode([
                'id' => FakeAuthenticator::CREDENTIAL_ID,
                'origin' => 'http://localhost',
                'alias' => null,
                'aaguid' => Uuid::NIL,
                'attestation_format' => 'none',
                'disabled_at' => null,
            ]),
            $json
        );
    }

    public function test_parses_correct_rp_id_as_domain_if_stored_as_url(): void
    {
        WebAuthnCredential::query()->whereKey(FakeAuthenticator::CREDENTIAL_ID)
            ->update(['rp_id' => 'https://my.custom.url/great?something=foo']);

        $credential = WebAuthnCredential::find(FakeAuthenticator::CREDENTIAL_ID);

        static::assertSame('my.custom.url', $credential->rp_id);
    }
}

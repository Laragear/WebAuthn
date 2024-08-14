<?php

/** @noinspection JsonEncodingApiUsageInspection */

namespace Tests\Assertion;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidator;
use Laragear\WebAuthn\Assertion\Validator\Pipes\CheckPublicKeyCounterCorrect;
use Laragear\WebAuthn\Assertion\Validator\Pipes\CheckPublicKeySignature;
use Laragear\WebAuthn\Assertion\Validator\Pipes\CheckUserInteraction;
use Laragear\WebAuthn\Attestation\AuthenticatorData;
use Laragear\WebAuthn\ByteBuffer;
use Laragear\WebAuthn\Challenge\Challenge;
use Laragear\WebAuthn\Events\CredentialAsserted;
use Laragear\WebAuthn\Events\CredentialCloned;
use Laragear\WebAuthn\Events\CredentialDisabled;
use Laragear\WebAuthn\Exceptions\AssertionException;
use Laragear\WebAuthn\JsonTransport;
use Laragear\WebAuthn\Models\WebAuthnCredential;
use Mockery;
use Ramsey\Uuid\Uuid;
use Symfony\Component\HttpFoundation\InputBag;
use Tests\DatabaseTestCase;
use Tests\FakeAuthenticator;
use Tests\Stubs\WebAuthnAuthenticatableUser;
use Throwable;

use function base64_decode;
use function base64_encode;
use function json_encode;
use function now;
use function session;

class ValidationTest extends DatabaseTestCase
{
    protected WebAuthnAuthenticatableUser $user;
    protected AssertionValidation $validation;
    protected AssertionValidator $validator;
    protected Challenge $challenge;

    protected function defineDatabaseSeeders(): void
    {
        $this->user = WebAuthnAuthenticatableUser::forceCreate([
            'name' => FakeAuthenticator::ATTESTATION_USER['displayName'],
            'email' => FakeAuthenticator::ATTESTATION_USER['name'],
            'password' => 'test_password',
        ]);

        DB::table('webauthn_credentials')->insert([
            'id' => FakeAuthenticator::CREDENTIAL_ID,
            'authenticatable_type' => WebAuthnAuthenticatableUser::class,
            'authenticatable_id' => 1,
            'user_id' => 'e8af6f703f8042aa91c30cf72289aa07',
            'counter' => 0,
            'rp_id' => 'localhost',
            'origin' => 'http://localhost',
            'aaguid' => Uuid::NIL,
            'attestation_format' => 'none',
            'public_key' => 'eyJpdiI6Imp0U0NVeFNNbW45KzEvMXpad2p2SUE9PSIsInZhbHVlIjoic0VxZ2I1WnlHM2lJakhkWHVkK2kzMWtibk1IN2ZlaExGT01qOElXMDdRTjhnVlR0TDgwOHk1S0xQUy9BQ1JCWHRLNzRtenNsMml1dVQydWtERjFEU0h0bkJGT2RwUXE1M1JCcVpablE2Y2VGV2YvVEE2RGFIRUE5L0x1K0JIQXhLVE1aNVNmN3AxeHdjRUo2V0hwREZSRTJYaThNNnB1VnozMlVXZEVPajhBL3d3ODlkTVN3bW54RTEwSG0ybzRQZFFNNEFrVytUYThub2IvMFRtUlBZamoyZElWKzR1bStZQ1IwU3FXbkYvSm1FU2FlMTFXYUo0SG9kc1BDME9CNUNKeE9IelE5d2dmNFNJRXBKNUdlVzJ3VHUrQWJZRFluK0hib0xvVTdWQ0ZISjZmOWF3by83aVJES1dxbU9Zd1lhRTlLVmhZSUdlWmlBOUFtcTM2ZVBaRWNKNEFSQUhENk5EaC9hN3REdnVFbm16WkRxekRWOXd4cVcvZFdKa2tlWWJqZWlmZnZLS0F1VEVCZEZQcXJkTExiNWRyQmxsZWtaSDRlT3VVS0ZBSXFBRG1JMjRUMnBKRXZxOUFUa2xxMjg2TEplUzdscVo2UytoVU5SdXk1OE1lcFN6aU05ZkVXTkdIM2tKM3Q5bmx1TGtYb1F5bGxxQVR3K3BVUVlia1VybDFKRm9lZDViNzYraGJRdmtUb2FNTEVGZmZYZ3lYRDRiOUVjRnJpcTVvWVExOHJHSTJpMnVBZ3E0TmljbUlKUUtXY2lSWDh1dE5MVDNRUzVRSkQrTjVJUU8rSGhpeFhRRjJvSEdQYjBoVT0iLCJtYWMiOiI5MTdmNWRkZGE5OTEwNzQ3MjhkYWVhYjRlNjk0MWZlMmI5OTQ4YzlmZWI1M2I4OGVkMjE1MjMxNjUwOWRmZTU2IiwidGFnIjoiIn0=',
            'updated_at' => now(),
            'created_at' => now(),
        ]);
    }

    protected function defineEnvironment($app): void
    {
        $this->travelTo(now()->startOfSecond());
    }

    protected function setUp(): void
    {
        $this->afterApplicationCreated(function (): void {
            // Force booting the model if not booted previously.
            WebAuthnCredential::make();

            $this->validator = new AssertionValidator($this->app);
            $this->validation = new AssertionValidation(new JsonTransport(FakeAuthenticator::assertionResponse()));

            $this->challenge = new Challenge(
                new ByteBuffer(base64_decode(FakeAuthenticator::ASSERTION_CHALLENGE)), 60, false,
            );

            $this->session(['_webauthn' => $this->challenge]);
        });

        parent::setUp();
    }

    protected function validate(): AssertionValidation
    {
        $this->validation->user = $this->user;

        return $this->validator->send($this->validation)->thenReturn();
    }

    public function test_assertion_creates_from_request_instance(): void
    {
        $request = Request::create('/');
        $request->headers->set('content-type', 'application/json');
        $request->setJson(new InputBag([
            ...FakeAuthenticator::assertionResponse(),
            'foo' => 'bar',
            'clientExtensionResults' => 'baz',
            'authenticatorAttachment' => 'quz',
        ]));

        $validation = AssertionValidation::fromRequest($request);

        static::assertEquals([
            ...FakeAuthenticator::assertionResponse(),
            'clientExtensionResults' => 'baz',
            'authenticatorAttachment' => 'quz',
        ], $validation->json->toArray());
    }

    public function test_assertion_allows_user_instance(): void
    {
        $this->validation->user = WebAuthnAuthenticatableUser::query()->first();

        static::assertInstanceOf(AssertionValidation::class, $this->validator->send($this->validation)->thenReturn());
    }

    public function test_assertion_allows_user_instance_without_user_handle(): void
    {
        $this->validation->user = WebAuthnAuthenticatableUser::query()->first();

        $response = FakeAuthenticator::assertionResponse();

        unset($response['response']['userHandle']);

        $this->validation->json = new JsonTransport($response);

        static::assertInstanceOf(AssertionValidation::class, $this->validator->send($this->validation)->thenReturn());
    }

    public function test_assertion_supports_ed25519_public_key(): void
    {
        $assertionResponse = FakeAuthenticator::assertionResponse();

        $assertionResponse['response']['signature'] = 'YCUMdR3mSYZl+f1/pb24wr8VYOC01A8rJ++38QFXuGl92GfwnLwdaldCuuWdIUsqOeTz5o8ucJsQqaxwFFsZAQ==';

        $publicKey = 'txSZLg1bc1ndhdq5tjlsbplNwm4wsKd4/IwCuEuSfPw=';

        DB::table('webauthn_credentials')->where('id', FakeAuthenticator::CREDENTIAL_ID)->update([
            'public_key' => Crypt::encryptString("-----BEGIN PUBLIC KEY-----\n$publicKey\n-----END PUBLIC KEY-----\n"),
        ]);

        $this->validation->json = new JsonTransport($assertionResponse);

        $this->validation->user = WebAuthnAuthenticatableUser::query()->first();

        static::assertInstanceOf(AssertionValidation::class, $this->validator->send($this->validation)->thenReturn());
    }

    public function test_assertion_supports_ed25519_public_key_with_16_byte_eddsa_header(): void
    {
        $assertionResponse = FakeAuthenticator::assertionResponse();

        $assertionResponse['response']['signature'] = 'YCUMdR3mSYZl+f1/pb24wr8VYOC01A8rJ++38QFXuGl92GfwnLwdaldCuuWdIUsqOeTz5o8ucJsQqaxwFFsZAQ==';

        $publicKey = 'MCowBQYDK2VwAyEAtxSZLg1bc1ndhdq5tjlsbplNwm4wsKd4/IwCuEuSfPw=';

        DB::table('webauthn_credentials')->where('id', FakeAuthenticator::CREDENTIAL_ID)->update([
            'public_key' => Crypt::encryptString("-----BEGIN PUBLIC KEY-----\n$publicKey\n-----END PUBLIC KEY-----\n"),
        ]);

        $this->validation->json = new JsonTransport($assertionResponse);

        $this->validation->user = WebAuthnAuthenticatableUser::query()->first();

        static::assertInstanceOf(AssertionValidation::class, $this->validator->send($this->validation)->thenReturn());
    }

    public function test_assertion_increases_counter(): void
    {
        static::assertInstanceOf(AssertionValidation::class, $this->validate());

        $this->assertDatabaseHas(WebAuthnCredential::class, [
            'id' => FakeAuthenticator::CREDENTIAL_ID,
            'counter' => 1,
        ]);
    }

    public function test_assertion_credential_without_zero_counter_is_valid_and_not_incremented(): void
    {
        $this->app->resolving(CheckPublicKeyCounterCorrect::class, function (): void {
            $this->validation->authenticatorData->counter = 0;
        });

        $this->validate();

        $this->assertDatabaseHas(WebAuthnCredential::class, [
            'id' => FakeAuthenticator::CREDENTIAL_ID,
            'counter' => 0,
        ]);
    }

    public function test_challenge_fails_if_not_found(): void
    {
        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Challenge does not exist.');

        $this->session(['_webauthn' => null]);

        $this->validate();
    }

    public function test_fails_if_challenge_exists_but_is_expired(): void
    {
        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Challenge does not exist.');

        $this->travelTo(now()->addMinute()->addSecond());

        $this->validate();
    }

    public function test_challenge_is_pulled_from_session(): void
    {
        $this->validate();

        static::assertNull(session('_webauthn'));
    }

    public function test_credential_id_check_fail_if_not_in_request_array(): void
    {
        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Credential is not on accepted list.');

        $this->challenge->properties['credentials'] = ['4bde1e58dba94de4ab307f46611165cb'];

        $this->validate();
    }

    public function test_credential_id_check_fails_if_doesnt_exist(): void
    {
        DB::table('webauthn_credentials')->where('id', FakeAuthenticator::CREDENTIAL_ID)->delete();

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Credential ID does not exist.');

        $this->validate();
    }

    public function test_credential_id_check_fails_if_disabled(): void
    {
        DB::table('webauthn_credentials')->where('id', FakeAuthenticator::CREDENTIAL_ID)->update([
            'disabled_at' => now(),
        ]);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Credential ID is blacklisted.');

        $this->validate();
    }

    public function test_credential_check_is_malformed_user_handle(): void
    {
        $assertionResponse = FakeAuthenticator::assertionResponse();

        $assertionResponse['response']['userHandle'] = 'ggggggggggggggggggggggggggggggg';

        $this->validation->json = new JsonTransport($assertionResponse);

        $this->validation->user = WebAuthnAuthenticatableUser::query()->first();

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage(
            'Assertion Error: The userHandle is not a valid hexadecimal UUID (32/36 characters).'
        );

        $this->validator->send($this->validation)->thenReturn();
    }

    public function test_credential_check_base64_user_handle(): void
    {
        $assertionResponse = FakeAuthenticator::assertionResponse();

        $assertionResponse['response']['userHandle'] = base64_encode($assertionResponse['response']['userHandle']);

        $this->validation->json = new JsonTransport($assertionResponse);

        $this->validation->user = WebAuthnAuthenticatableUser::query()->first();

        static::assertInstanceOf(AssertionValidation::class, $this->validator->send($this->validation)->thenReturn());
    }

    public function test_credential_check_is_not_for_user_id(): void
    {
        DB::table('webauthn_credentials')->where('id', FakeAuthenticator::CREDENTIAL_ID)->update([
            'user_id' => '4bde1e58dba94de4ab307f46611165cb',
        ]);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: User ID is not owner of the stored credential.');

        $this->validate();
    }

    public function test_credential_check_fails_if_not_for_user_instance(): void
    {
        $this->user->setAttribute('id', 2)->save();

        $this->validation->user = $this->user;

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: User is not owner of the stored credential.');

        $this->validate();
    }

    public function test_type_check_fails_if_not_public_key(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['type'] = 'invalid';

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Response type is not [public-key].');

        $this->validate();
    }

    public function test_authenticator_data_fails_if_empty(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['authenticatorData'] = '';

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Authenticator Data does not exist or is empty.');

        $this->validate();
    }

    public function test_authenticator_data_fails_if_invalid(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['authenticatorData'] = 'invalid';

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Authenticator Data: Invalid input.');

        $this->validate();
    }

    public function test_compiling_client_data_json_fails_if_invalid(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = 'foo';

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Client Data JSON is invalid or malformed.');

        $this->validate();
    }

    public function test_compiling_client_data_json_fails_if_empty(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = ByteBuffer::encodeBase64Url(json_encode([]));

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Client Data JSON is empty.');

        $this->validate();
    }

    public function test_compiling_client_data_json_fails_if_type_missing(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = ByteBuffer::encodeBase64Url(json_encode([
            'origin' => '', 'challenge' => '',
        ]));

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Client Data JSON does not contain the [type] key.');

        $this->validate();
    }

    public function test_compiling_client_data_json_fails_if_origin_missing(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(json_encode(['type' => '', 'challenge' => '']));

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Client Data JSON does not contain the [origin] key.');

        $this->validate();
    }

    public function test_compiling_client_data_json_fails_if_challenge_missing(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(json_encode(['type' => '', 'origin' => '']));

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Client Data JSON does not contain the [challenge] key.');

        $this->validate();
    }

    public function test_action_checks_fails_if_not_webauthn_create(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'invalid',
                'origin' => '',
                'challenge' => '',
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Client Data type is not [webauthn.get].');

        $this->validate();
    }

    public function test_check_challenge_fails_if_challenge_is_empty(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.get',
                'origin' => 'https://localhost',
                'challenge' => '',
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Response has an empty challenge.');

        $this->validate();
    }

    public function test_check_challenge_fails_if_challenge_is_not_equal(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.get',
                'origin' => 'https://localhost',
                'challenge' => 'invalid',
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Response challenge is not equal.');

        $this->validate();
    }

    public function test_check_origin_matches_non_url(): void
    {
        $this->app->make('config')->set('webauthn.origins', ['foo', 'bar.baz']);

        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.get',
                'origin' => 'foo',
                'challenge' => FakeAuthenticator::ASSERTION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        // The signature will not match since it's tailored to the origin itself.
        $this->mock(CheckPublicKeySignature::class, function (Mockery\MockInterface $mock): void {
            $mock->expects('handle')->andReturnUsing(fn ($validation, $closure) => $closure($validation));
        });

        static::assertInstanceOf(AssertionValidation::class, $this->validate());
    }

    public function test_check_origin_matches_non_url_from_string(): void
    {
        $this->app->make('config')->set('webauthn.origins', 'foo,bar.baz');

        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.get',
                'origin' => 'foo',
                'challenge' => FakeAuthenticator::ASSERTION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        // The signature will not match since it's tailored to the origin itself.
        $this->mock(CheckPublicKeySignature::class, function (Mockery\MockInterface $mock): void {
            $mock->expects('handle')->andReturnUsing(fn ($validation, $closure) => $closure($validation));
        });

        static::assertInstanceOf(AssertionValidation::class, $this->validate());
    }

    public function test_check_origin_doesnt_match_subdomain_from_non_origin_url(): void
    {
        $this->app->make('config')->set('webauthn.origins', 'foo,bar.baz');

        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.get',
                'origin' => 'bar.foo',
                'challenge' => FakeAuthenticator::ASSERTION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Response origin not allowed for this app.');

        $this->validate();
    }

    public function test_check_origin_fails_if_empty(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.get',
                'origin' => '',
                'challenge' => FakeAuthenticator::ASSERTION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Response has an empty origin.');

        $this->validate();
    }

    public function test_check_origin_fails_if_invalid_host(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.get',
                'origin' => 'invalid',
                'challenge' => FakeAuthenticator::ASSERTION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Response origin not allowed for this app.');

        $this->validate();
    }

    public function test_check_origin_fails_if_unsecure(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        /** @noinspection HttpUrlsUsage */
        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.get',
                'origin' => 'http://unsecure.com',
                'challenge' => FakeAuthenticator::ASSERTION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage(
            'Assertion Error: Response origin not made from a secure server (localhost or HTTPS).'
        );

        $this->validate();
    }

    public function test_rp_id_fails_if_empty(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.get',
                'origin' => '',
                'challenge' => FakeAuthenticator::ASSERTION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Response has an empty origin.');

        $this->validate();
    }

    public function test_rp_id_fails_if_not_equal(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.get',
                'origin' => 'https://otherhost.com',
                'challenge' => FakeAuthenticator::ASSERTION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Response origin not allowed for this app.');

        $this->validate();
    }

    public function test_rp_id_fails_if_not_contained(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.get',
                'origin' => 'https://invalidlocalhost',
                'challenge' => FakeAuthenticator::ASSERTION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Response origin not allowed for this app.');

        $this->validate();
    }

    public function test_rp_id_passes_if_subdomain(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.get',
                'origin' => 'http://valid.localhost:9780',
                'challenge' => FakeAuthenticator::ASSERTION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        // The signature will not match since it's tailored to the origin itself.
        $this->mock(CheckPublicKeySignature::class, function (Mockery\MockInterface $mock): void {
            $mock->expects('handle')->andReturnUsing(fn ($validation, $closure) => $closure($validation));
        });

        static::assertInstanceOf(AssertionValidation::class, $this->validate());
    }

    public function test_rp_id_fails_if_hash_not_same(): void
    {
        DB::table('webauthn_credentials')->where('id', FakeAuthenticator::CREDENTIAL_ID)->update([
            'rp_id' => 'https://otherorigin.com',
        ]);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Response has different Relying Party ID hash.');

        $this->validate();
    }

    public function test_check_user_interaction_fails_if_user_not_present(): void
    {
        $this->app->resolving(CheckUserInteraction::class, function (): void {
            $this->validation->authenticatorData = Mockery::mock(AuthenticatorData::class);

            $this->validation->authenticatorData->expects('wasUserAbsent')->andReturnTrue();
        });

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Response did not have the user present.');

        $this->validate();
    }

    public function test_check_user_interaction_fails_if_user_verification_was_required(): void
    {
        $this->challenge->verify = true;

        $this->app->resolving(CheckUserInteraction::class, function (): void {
            $this->validation->authenticatorData = Mockery::mock(AuthenticatorData::class);

            $this->validation->authenticatorData->expects('wasUserAbsent')->andReturnFalse();
            $this->validation->authenticatorData->expects('wasUserNotVerified')->andReturnTrue();
        });

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Response did not verify the user.');

        $this->validate();
    }

    public function test_signature_fails_if_credential_public_key_invalid(): void
    {
        DB::table('webauthn_credentials')->where('id', FakeAuthenticator::CREDENTIAL_ID)->update([
            'public_key' => Crypt::encryptString('invalid'),
        ]);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessageMatches('/^Assertion Error: Public key is invalid.*/m');

        $this->validate();
    }

    public function test_signature_fails_if_response_signature_empty(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['signature'] = base64_encode('');

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Signature is empty.');

        $this->validate();
    }

    public function test_signature_fails_if_invalid(): void
    {
        DB::table('webauthn_credentials')->where('id', FakeAuthenticator::CREDENTIAL_ID)->update([
            'public_key' => Crypt::encryptString('-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnBadZo+CnNdUHvzCWuLN
TFsXTCjsHH5A+aUtIImsJsbTKmYsYtOuiOwEgcGglKEJV0MwzV4v2SDQzSirwLEr
isis4qV6Q3a0ZyZcYhgyMzvkk5CtDhpzxhsmFwiMSGt9gVRE8cOxGDQX2jTPfqyk
xZTkoXKEHevq8kl5PBCPsaWskrWsySw9mmqNCmIjhE2Evgarm0Xq7yq5h62H2ZzF
T3U5C0H32I9cTPk6f/SVke+GMseVRiLleltJMNl0CAcKGBmJpQfeLFlKmOc15Wql
wuMegjGULD9dPQvZS5uX+P0bHYfXq5V/HTwrR9FmkEdhq5YB9nE6RkE6Fbs5f+LI
hQIDAQAB
-----END PUBLIC KEY-----'),
        ]);

        $this->expectException(AssertionException::class);

        $this->expectExceptionMessageMatches('/^Assertion Error: Signature is invalid.*/m');

        $this->validate();
    }

    public function test_counter_fails_if_authenticator_counts_same_as_stored_counter(): void
    {
        $event = Event::fake([CredentialCloned::class, CredentialDisabled::class]);

        DB::table('webauthn_credentials')->where('id', FakeAuthenticator::CREDENTIAL_ID)->update([
            'counter' => 1,
        ]);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Credential counter not over stored counter.');

        try {
            $this->validate();
        } catch (Throwable $e) {
            $event->assertDispatched(CredentialCloned::class);
            $event->assertDispatched(CredentialDisabled::class);
            $this->assertDatabaseHas(WebAuthnCredential::class, [
                'id' => FakeAuthenticator::CREDENTIAL_ID,
                'disabled_at' => now()->toDateTimeString(),
            ]);

            throw $e;
        }
    }

    public function test_counter_fails_if_authenticator_counts_below_as_stored_counter(): void
    {
        $event = Event::fake([CredentialCloned::class, CredentialDisabled::class]);

        DB::table('webauthn_credentials')->where('id', FakeAuthenticator::CREDENTIAL_ID)->update([
            'counter' => 2,
        ]);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Credential counter not over stored counter.');

        try {
            $this->validate();
        } catch (Throwable $e) {
            $event->assertDispatched(CredentialCloned::class);
            $event->assertDispatched(CredentialDisabled::class);
            $this->assertDatabaseHas(WebAuthnCredential::class, [
                'id' => FakeAuthenticator::CREDENTIAL_ID,
                'disabled_at' => now()->toDateTimeString(),
            ]);

            throw $e;
        }
    }

    public function test_assertion_dispatches_event_with_user()
    {
        $event = Event::fake(CredentialAsserted::class);

        $this->validate();

        $event->assertDispatched(CredentialAsserted::class, function (CredentialAsserted $event): bool {
            return $event->user === $this->user
                && $this->validation->credential === $event->credential;
        });
    }

    public function test_assertion_dispatches_event_without_user()
    {
        $event = Event::fake(CredentialAsserted::class);

        $this->validation->user = null;

        $this->validator->send($this->validation)->thenReturn();

        $event->assertDispatched(CredentialAsserted::class, function (CredentialAsserted $event): bool {
            return $event->user === null
                && $this->validation->credential === $event->credential;
        });
    }
}

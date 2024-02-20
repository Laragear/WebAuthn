<?php /** @noinspection JsonEncodingApiUsageInspection */

namespace Tests\Assertion;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidator;
use Laragear\WebAuthn\Assertion\Validator\Pipes\CheckPublicKeyCounterCorrect;
use Laragear\WebAuthn\Assertion\Validator\Pipes\CheckUserInteraction;
use Laragear\WebAuthn\Attestation\AuthenticatorData;
use Laragear\WebAuthn\ByteBuffer;
use Laragear\WebAuthn\Challenge;
use Laragear\WebAuthn\Events\CredentialCloned;
use Laragear\WebAuthn\Events\CredentialDisabled;
use Laragear\WebAuthn\Exceptions\AssertionException;
use Laragear\WebAuthn\Models\WebAuthnCredential;
use Mockery;
use Ramsey\Uuid\Uuid;
use Symfony\Component\HttpFoundation\ParameterBag;
use Tests\FakeAuthenticator;
use Tests\Stubs\WebAuthnAuthenticatableUser;
use Tests\TestCase;
use Throwable;
use function base64_decode;
use function base64_encode;
use function json_encode;
use function now;
use function session;

class ValidationTest extends TestCase
{
    protected Request $request;
    protected WebAuthnAuthenticatableUser $user;
    protected AssertionValidation $validation;
    protected AssertionValidator $validator;
    protected Challenge $challenge;

    protected function setUp(): void
    {
        parent::setUp();

        $this->request = Request::create(
            'https://test.app/webauthn/create', 'POST', content: json_encode(FakeAuthenticator::assertionResponse())
        );

        $this->user = WebAuthnAuthenticatableUser::forceCreate([
            'name' => FakeAuthenticator::ATTESTATION_USER['displayName'],
            'email' => FakeAuthenticator::ATTESTATION_USER['name'],
            'password' => 'test_password',
        ]);

        $this->validator = new AssertionValidator($this->app);
        $this->validation = new AssertionValidation($this->request);

        $this->travelTo(now()->startOfSecond());

        $this->challenge = new Challenge(
            new ByteBuffer(base64_decode(FakeAuthenticator::ASSERTION_CHALLENGE)), 60, false,
        );

        $this->session(['_webauthn' => $this->challenge]);

        $this->request->setLaravelSession($this->app->make('session.store'));

        $this->credential = DB::table('webauthn_credentials')->insert([
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

    protected function validate(): AssertionValidation
    {
        return $this->validator->send($this->validation)->thenReturn();
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

        $this->request->setJson(new ParameterBag($response));

        static::assertInstanceOf(AssertionValidation::class, $this->validator->send($this->validation)->thenReturn());
    }

    public function test_assertion_increases_counter(): void
    {
        static::assertInstanceOf(AssertionValidation::class, $this->validator->send($this->validation)->thenReturn());

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

    public function test_credential_check_if_not_for_user_id(): void
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

        $this->request->setJson(new ParameterBag($invalid));

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Response type is not [public-key].');

        $this->validate();
    }

    public function test_authenticator_data_fails_if_empty(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['authenticatorData'] = '';

        $this->request->setJson(new ParameterBag($invalid));

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Authenticator Data does not exist or is empty.');

        $this->validate();
    }

    public function test_authenticator_data_fails_if_invalid(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['authenticatorData'] = 'invalid';

        $this->request->setJson(new ParameterBag($invalid));

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Authenticator Data: Invalid input.');

        $this->validate();
    }

    public function test_compiling_client_data_json_fails_if_invalid(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = 'foo';

        $this->request->setJson(new ParameterBag($invalid));

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Client Data JSON is invalid or malformed.');

        $this->validate();
    }

    public function test_compiling_client_data_json_fails_if_empty(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(json_encode([]));

        $this->request->setJson(new ParameterBag($invalid));

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Client Data JSON is empty.');

        $this->validate();
    }

    public function test_compiling_client_data_json_fails_if_type_missing(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(json_encode(['origin' => '', 'challenge' => '']));

        $this->request->setJson(new ParameterBag($invalid));

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Client Data JSON does not contain the [type] key.');

        $this->validate();
    }

    public function test_compiling_client_data_json_fails_if_origin_missing(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(json_encode(['type' => '', 'challenge' => '']));

        $this->request->setJson(new ParameterBag($invalid));

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Client Data JSON does not contain the [origin] key.');

        $this->validate();
    }

    public function test_compiling_client_data_json_fails_if_challenge_missing(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(json_encode(['type' => '', 'origin' => '']));

        $this->request->setJson(new ParameterBag($invalid));

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Client Data JSON does not contain the [challenge] key.');

        $this->validate();
    }

    public function test_action_checks_fails_if_not_webauthn_create(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode(['type' => 'invalid', 'origin' => '', 'challenge' => ''])
        );

        $this->request->setJson(new ParameterBag($invalid));

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Client Data type is not [webauthn.get].');

        $this->validate();
    }

    public function test_check_challenge_fails_if_challenge_is_empty(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode(['type' => 'webauthn.get', 'origin' => 'https://localhost', 'challenge' => ''])
        );

        $this->request->setJson(new ParameterBag($invalid));

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Response has an empty challenge.');

        $this->validate();
    }

    public function test_check_challenge_fails_if_challenge_is_not_equal(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode(['type' => 'webauthn.get', 'origin' => 'https://localhost', 'challenge' => 'invalid'])
        );

        $this->request->setJson(new ParameterBag($invalid));

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Response challenge is not equal.');

        $this->validate();
    }

    public function test_check_origin_fails_if_empty(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode(['type' => 'webauthn.get', 'origin' => '', 'challenge' => FakeAuthenticator::ASSERTION_CHALLENGE])
        );

        $this->request->setJson(new ParameterBag($invalid));

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Response has an empty origin.');

        $this->validate();
    }

    public function test_check_origin_fails_if_invalid_host(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode(['type' => 'webauthn.get', 'origin' => 'invalid', 'challenge' => FakeAuthenticator::ASSERTION_CHALLENGE])
        );

        $this->request->setJson(new ParameterBag($invalid));

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Response origin is invalid.');

        $this->validate();
    }

    public function test_check_origin_fails_if_unsecure(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        /** @noinspection HttpUrlsUsage */
        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode(['type' => 'webauthn.get', 'origin' => 'http://unsecure.com', 'challenge' => FakeAuthenticator::ASSERTION_CHALLENGE])
        );

        $this->request->setJson(new ParameterBag($invalid));

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Response not made to a secure server (localhost or HTTPS).');

        $this->validate();
    }

    public function test_rp_id_fails_if_empty(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.get',
                'origin' => '',
                'challenge' => FakeAuthenticator::ASSERTION_CHALLENGE
            ])
        );

        $this->request->setJson(new ParameterBag($invalid));

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
                'challenge' => FakeAuthenticator::ASSERTION_CHALLENGE
            ])
        );

        $this->request->setJson(new ParameterBag($invalid));

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Relying Party ID not scoped to current.');

        $this->validate();
    }

    public function test_rp_id_fails_if_not_contained(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.get',
                'origin' => 'https://invalidlocalhost',
                'challenge' => FakeAuthenticator::ASSERTION_CHALLENGE
            ])
        );

        $this->request->setJson(new ParameterBag($invalid));

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Relying Party ID not scoped to current.');

        $this->validate();
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
            'public_key' => Crypt::encryptString('invalid')
        ]);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Stored Public Key is invalid.');

        $this->validate();
    }

    public function test_signature_fails_if_response_signature_empty(): void
    {
        $invalid = FakeAuthenticator::assertionResponse();

        $invalid['response']['signature'] = base64_encode('');

        $this->request->setJson(new ParameterBag($invalid));

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Signature is empty.');

        $this->validate();
    }

    public function test_signature_fails_if_invalid(): void
    {
        DB::table('webauthn_credentials')->where('id', FakeAuthenticator::CREDENTIAL_ID)->update([
            'public_key' => Crypt::encryptString("-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnBadZo+CnNdUHvzCWuLN
TFsXTCjsHH5A+aUtIImsJsbTKmYsYtOuiOwEgcGglKEJV0MwzV4v2SDQzSirwLEr
isis4qV6Q3a0ZyZcYhgyMzvkk5CtDhpzxhsmFwiMSGt9gVRE8cOxGDQX2jTPfqyk
xZTkoXKEHevq8kl5PBCPsaWskrWsySw9mmqNCmIjhE2Evgarm0Xq7yq5h62H2ZzF
T3U5C0H32I9cTPk6f/SVke+GMseVRiLleltJMNl0CAcKGBmJpQfeLFlKmOc15Wql
wuMegjGULD9dPQvZS5uX+P0bHYfXq5V/HTwrR9FmkEdhq5YB9nE6RkE6Fbs5f+LI
hQIDAQAB
-----END PUBLIC KEY-----")
        ]);

        $this->expectException(AssertionException::class);
        $this->expectExceptionMessage('Assertion Error: Signature is invalid.');

        $this->validate();
    }

    public function test_counter_fails_if_authenticator_counts_same_as_stored_counter(): void
    {
        $event = Event::fake([CredentialCloned::class, CredentialDisabled::class]);

        DB::table('webauthn_credentials')->where('id', FakeAuthenticator::CREDENTIAL_ID)->update([
            'counter' => 1
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
            'counter' => 2
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
}

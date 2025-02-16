<?php

namespace Laragear\WebAuthn\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Database\Schema\Blueprint;
use Laragear\MetaModel\CustomMigration;
use Laragear\MetaModel\HasCustomization;
use Laragear\WebAuthn\Enums\Formats;
use Laragear\WebAuthn\Events\CredentialDisabled;
use Laragear\WebAuthn\Events\CredentialEnabled;

use function parse_url;

use const PHP_URL_HOST;

/**
 * @mixin \Illuminate\Database\Eloquent\Builder
 *
 * @method \Illuminate\Database\Eloquent\Builder|static newQuery()
 * @method static \Illuminate\Database\Eloquent\Builder|static query()
 * @method static \Laragear\WebAuthn\Models\WebAuthnCredential make(array $attributes = [])
 * @method static \Laragear\WebAuthn\Models\WebAuthnCredential create(array $attributes = [])
 * @method static \Laragear\WebAuthn\Models\WebAuthnCredential forceCreate(array $attributes)
 * @method static \Laragear\WebAuthn\Models\WebAuthnCredential forceCreateQuietly(array $attributes = [])
 * @method \Laragear\WebAuthn\Models\WebAuthnCredential|null first($columns = ['*'], string ...$columns)
 * @method \Laragear\WebAuthn\Models\WebAuthnCredential firstOrNew(array $attributes = [], array $values = [])
 * @method \Laragear\WebAuthn\Models\WebAuthnCredential firstOrFail($columns = ['*'])
 * @method \Laragear\WebAuthn\Models\WebAuthnCredential firstOrCreate(array $attributes, array $values = [])
 * @method \Laragear\WebAuthn\Models\WebAuthnCredential firstOr($columns = ['*'], \Closure|null $callback = null)
 * @method \Laragear\WebAuthn\Models\WebAuthnCredential firstWhere($column, $operator = null, $value = null, $boolean = 'and')
 * @method \Laragear\WebAuthn\Models\WebAuthnCredential updateOrCreate(array $attributes, array $values = [])
 * @method \Laragear\WebAuthn\Models\WebAuthnCredential createOrFirst(array $attributes, array $values = [])
 * @method \Laragear\WebAuthn\Models\WebAuthnCredential sole($columns = ['*'])
 * @method \Laragear\WebAuthn\Models\WebAuthnCredential findOrNew($id, $columns = ['*'])
 * @method \Illuminate\Database\Eloquent\Collection<int, static>|static[]|static|null find($id, $columns = ['*'])
 * @method \Illuminate\Database\Eloquent\Collection<int, static>|static[]|static findOrFail($id, $columns = ['*'])
 * @method \Illuminate\Database\Eloquent\Collection<int, static>|static[]|static findOr($id, $columns = ['*'], \Closure|null $callback = null)
 * @method \Illuminate\Database\Eloquent\Collection<int, static>|static[] findMany($id, $columns = ['*'])
 * @method \Illuminate\Database\Eloquent\Collection<int, static>|static[] fromQuery($query, $bindings = [])
 * @method \Illuminate\Support\LazyCollection<int, static>|static[] lazy(int $chunkSize = 1000)
 * @method \Illuminate\Support\LazyCollection<int, static>|static[] lazyById(int $chunkSize = 1000, string|null $column = null, string|null $alias = null)
 * @method \Illuminate\Support\LazyCollection<int, static>|static[] lazyByIdDesc(int $chunkSize = 1000, string|null $column = null, string|null $alias = null)
 *
 * @property-read string $id
 * @property-read string $user_id
 * @property string|null $alias
 * @property-read int $counter
 * @property-read string $rp_id
 * @property-read string $origin
 * @property-read array<int, string>|null $transports
 * @property-read string $aaguid
 * @property-read string $public_key
 * @property-read string $attestation_format
 * @property-read array<int, string> $certificates
 * @property-read \Illuminate\Support\Carbon|null $disabled_at
 * @property-read \Laragear\WebAuthn\ByteBuffer $binary_id
 * @property-read \Illuminate\Support\Carbon $updated_at
 * @property-read \Illuminate\Support\Carbon $created_at
 * @property-read \Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable $authenticatable
 *
 * @method \Illuminate\Database\Eloquent\Builder|static whereEnabled()
 * @method \Illuminate\Database\Eloquent\Builder|static whereDisabled()
 *
 * @phpstan-consistent-constructor
 */
class WebAuthnCredential extends Model
{
    use HasCustomization;

    /**
     * The table associated with the model.
     *
     * @var string|null
     */
    protected $table = 'webauthn_credentials';

    /**
     * The "type" of the primary key ID.
     *
     * @var string
     */
    protected $keyType = 'string';

    /**
     * Indicates if the IDs are auto-incrementing.
     *
     * @var bool
     */
    public $incrementing = false;

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'counter' => 'int',
        'transports' => 'array',
        'public_key' => 'encrypted',
        'certificates' => 'array',
        'disabled_at' => 'timestamp',
    ];

    /**
     * The attributes that should be visible in serialization.
     *
     * @var array<int, string>
     */
    protected $visible = ['id', 'origin', 'alias', 'aaguid', 'attestation_format', 'disabled_at'];

    /**
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable, $this>
     */
    public function authenticatable(): MorphTo // @phpstan-ignore-line
    {
        return $this->morphTo('authenticatable'); // @phpstan-ignore-line
    }

    /**
     * Filter the query by enabled credentials.
     */
    protected function scopeWhereEnabled(Builder $query): Builder
    {
        return $query->whereNull('disabled_at'); // @phpstan-ignore-line
    }

    /**
     * Filter the query by disabled credentials.
     */
    protected function scopeWhereDisabled(Builder $query): Builder
    {
        return $query->whereNotNull('disabled_at'); // @phpstan-ignore-line
    }

    /**
     * Check if the credential is enabled.
     */
    public function isEnabled(): bool
    {
        return null === $this->attributes['disabled_at'];
    }

    /**
     * Check if the credential is disabled.
     */
    public function isDisabled(): bool
    {
        return ! $this->isEnabled();
    }

    /**
     * Enables the credential to be used with WebAuthn.
     */
    public function enable(): void
    {
        $wasDisabled = (bool) $this->attributes['disabled_at'];

        $this->attributes['disabled_at'] = null;

        $this->save();

        if ($wasDisabled) {
            CredentialEnabled::dispatch($this);
        }
    }

    /**
     * Disables the credential for WebAuthn.
     */
    public function disable(): void
    {
        $wasEnabled = ! $this->attributes['disabled_at'];

        $this->setAttribute('disabled_at', $this->freshTimestamp())->save();

        if ($wasEnabled) {
            CredentialDisabled::dispatch($this);
        }
    }

    /**
     * Sets the counter for this WebAuthn Credential.
     */
    public function syncCounter(int $counter): void
    {
        $this->attributes['counter'] = $counter;

        $this->save();
    }

    /**
     * Mutate the "rp_id" attribute.
     */
    protected function rpId(): Attribute
    {
        return Attribute::get(static function (string $rpId): string {
            return ($domain = parse_url($rpId, PHP_URL_HOST)) ? $domain : $rpId;
        });
    }

    /**
     * @inheritDoc
     */
    public static function migration(): CustomMigration
    {
        return new CustomMigration(new static, function (Blueprint $table): void { // @phpstan-ignore-line
            // Here we set the PublicKeyCredential ID generated by the authenticator as string.
            // This way it's easier and faster for the database to find the right credential
            // on the Assertion procedure as the device returns which credential it used.
            $table->string('id', 510)->primary();

            $this->createMorph($table, 'authenticatable', 'webauthn_user_index'); // @phpstan-ignore-line

            // When requesting to create a credential, the app will set a "user handle" to be
            // a UUID to anonymize the user personal information. If a second credential is
            // created, the first UUID is copied to the new one, keeping the association.
            $table->uuid('user_id');

            // The app may allow the user to name or rename a credential to a friendly name,
            // like "John's iPhone" or "Office Computer". This column is nullable, so it's
            // up to the app to use an alias. Otherwise, the app can use custom columns.
            $table->string('alias')->nullable();

            // Allows to detect cloned credentials when these do not share the same counter.
            $table->unsignedBigInteger('counter')->nullable();
            // Who created the credential? Should be the same reported by the Authenticator.
            $table->string('rp_id');
            // Where the credential was created? Should be the same reported by the Authenticator.
            $table->string('origin');
            // The available "ways to transmit" the public key between the browser and Authenticator.
            // It may be generated by the authenticator when it creates it, that's why is nullable.
            // On assertion, this will allow the authenticator where to look for the private key.
            $table->json('transports')->nullable();
            // The "type" or "properties" of the authenticator. Sometimes these are zeroes or null.
            $table->uuid('aaguid')->nullable(); // GUID are essentially UUID

            // This is the public key the server will use to verify the challenges are corrected.
            $table->text('public_key');
            // The attestation of the public key.
            $table->string('attestation_format')->default(Formats::None->value);
            // This would hold the certificate chain for other different attestation formats.
            $table->json('certificates')->nullable();

            // A way to disable the credential without deleting it.
            $table->timestamp('disabled_at')->nullable();
            $table->timestamps();
        });
    }
}

<?php

namespace Laragear\WebAuthn\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Console\Isolatable;
use Illuminate\Encryption\Encrypter;
use Laragear\WebAuthn\Models\WebAuthnCredential;
use Symfony\Component\Console\Attribute\AsCommand;
use function substr;
use const SIGABRT;
use const SIGQUIT;

#[AsCommand(name: 'webauthn:re-encrypt')]
class ReEncryptCommand extends Command implements Isolatable
{
    /**
     * The console command signature.
     *
     * @var string
     */
    protected $signature = 'webauthn:re-encrypt
                {key : The new Application Key to use to re-encrypt the Passkeys}
                {--cipher? : The cipher mechanism to encode the Passkeys}
                {--chunks=1000 : The number of Passkeys to retrieve from the database in each chunk}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Re-encrypts WebAuthn Credentials (Passkeys) with a new key';

    /**
     * If the command should terminate by an external signal.
     *
     * @var bool
     */
    protected bool $shouldTerminate = false;

    /**
     * Execute the console command.
     *
     * @throws \Throwable
     */
    public function handle(): void
    {
        $this->trap([SIGTERM, SIGQUIT, SIGABRT], function (): void {
            $this->shouldTerminate = true;
        });

        $encrypter = $this->createEncrypterWithNewKey();

        $this->info('Using ...' . substr($this->option('key'), -5) . ' as re-encryption key');

        /** @var \Illuminate\Support\LazyCollection<\Laragear\WebAuthn\Models\WebAuthnCredential> $credentials */
        $credentials = WebAuthnCredential::query()->select(['id', 'public_key'])->lazy($this->option('chunks'));

        $bar = $this->output->createProgressBar($credentials->count());

        $bar->start();

        foreach ($credentials as $credential) {
            if ($this->shouldTerminate) {
                $progress = $bar->getProgress();

                $bar->finish();

                $this->warn("The command was stopped after $progress re-encrypted credentials.");
            }

            $credential->setRawAttributes([
                $credential->getKeyName() => $credential->getKey(),
                'public_key' => $encrypter->encrypt($credential->public_key)
            ])->saveOrFail();

            $bar->advance();
        }

        $this->info("Re-encrypted {$credentials->count()} credentials.");
    }

    /**
     * Creates a new encrypter with the issued encryption key.
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function createEncrypterWithNewKey(): Encrypter
    {
        return new Encrypter(
            $this->option('key'), $this->option('cipher') ?: $this->laravel->make('config')->get('app')
        );
    }
}

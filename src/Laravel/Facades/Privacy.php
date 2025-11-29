<?php

declare(strict_types=1);

namespace PrivacyShield\Laravel\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static string|array mask(string|array|object $data)
 * @method static array scan(string $text)
 * @method static array scanDetailed(string $text)
 * @method static string|array pseudonymize(string|array|object $data, ?string $seed = null)
 * @method static bool hasSensitiveData(string $text)
 * @method static string redact(string $text)
 *
 * @see \PrivacyShield\Privacy
 */
class Privacy extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'privacy-shield';
    }
}

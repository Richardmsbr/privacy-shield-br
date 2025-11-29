<?php

declare(strict_types=1);

namespace PrivacyShield\Laravel\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use PrivacyShield\Privacy;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware para sanitizar logs de requisições
 *
 * Remove dados sensíveis dos logs de requisição,
 * útil para compliance LGPD em ambientes de debug.
 *
 * Uso: Route::post('/checkout', ...)->middleware('privacy.log');
 */
class SanitizeLogging
{
    public function handle(Request $request, Closure $next): Response
    {
        // Registra request sanitizado
        if (config('privacy-shield.log_requests', false)) {
            $sanitizedInput = Privacy::mask($request->all());

            Log::debug('Request sanitizado', [
                'method' => $request->method(),
                'path' => $request->path(),
                'input' => $sanitizedInput,
            ]);
        }

        return $next($request);
    }
}

<?php

declare(strict_types=1);

namespace PrivacyShield\Laravel\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use PrivacyShield\Privacy;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware para mascarar dados sensíveis em respostas JSON
 *
 * Útil para APIs onde você quer garantir que dados sensíveis
 * nunca vazem para o cliente.
 *
 * Uso: Route::get('/users', ...)->middleware('privacy.mask');
 */
class MaskSensitiveData
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        // Só processa respostas JSON
        if ($response instanceof JsonResponse) {
            $data = $response->getData(true);

            if (is_array($data)) {
                $masked = Privacy::mask($data);
                $response->setData($masked);
            }
        }

        return $response;
    }
}

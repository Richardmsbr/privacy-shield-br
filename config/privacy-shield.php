<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Caractere de Máscara
    |--------------------------------------------------------------------------
    |
    | Caractere usado para substituir dados sensíveis.
    | Padrão: * (asterisco)
    |
    */
    'mask_char' => env('PRIVACY_MASK_CHAR', '*'),

    /*
    |--------------------------------------------------------------------------
    | Texto de Redação
    |--------------------------------------------------------------------------
    |
    | Texto usado quando dados são completamente removidos (redact).
    |
    */
    'redact_text' => env('PRIVACY_REDACT_TEXT', '[REMOVIDO]'),

    /*
    |--------------------------------------------------------------------------
    | Detectores Ativos
    |--------------------------------------------------------------------------
    |
    | Habilita/desabilita detecção de tipos específicos de dados.
    |
    */
    'detectors' => [
        'cpf' => true,
        'cnpj' => true,
        'email' => true,
        'phone' => true,
        'pix' => true,
        'credit_card' => true,
        'name' => false, // Requer NLP, desabilitado por padrão
    ],

    /*
    |--------------------------------------------------------------------------
    | Mascarar Domínio de Email
    |--------------------------------------------------------------------------
    |
    | Se true, mascara também o domínio do email.
    | Se false, mantém o domínio visível.
    |
    */
    'mask_email_domain' => true,

    /*
    |--------------------------------------------------------------------------
    | Logging de Requisições
    |--------------------------------------------------------------------------
    |
    | Se true, o middleware SanitizeLogging registra requisições sanitizadas.
    | Útil para debug em desenvolvimento.
    |
    */
    'log_requests' => env('PRIVACY_LOG_REQUESTS', false),

    /*
    |--------------------------------------------------------------------------
    | Locale
    |--------------------------------------------------------------------------
    |
    | Locale para geração de dados pseudonimizados.
    |
    */
    'locale' => env('PRIVACY_LOCALE', 'pt_BR'),
];

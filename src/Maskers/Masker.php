<?php

declare(strict_types=1);

namespace PrivacyShield\Maskers;

use PrivacyShield\Detectors\Detector;

/**
 * Mascarador de dados sensíveis
 *
 * Substitui dados pessoais por versões mascaradas, mantendo
 * parte da informação visível para contexto.
 */
class Masker
{
    private array $config;
    private Detector $detector;
    private string $maskChar;
    private string $redactText;

    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->detector = new Detector($config);
        $this->maskChar = $config['mask_char'] ?? '*';
        $this->redactText = $config['redact_text'] ?? '[REMOVIDO]';
    }

    /**
     * Mascara todos os dados sensíveis em uma string
     */
    public function maskString(string $text): string
    {
        $detected = $this->detector->scanDetailed($text);

        // Processa do fim para o início para manter posições corretas
        $detected = array_reverse($detected);

        foreach ($detected as $item) {
            $masked = $this->maskValue($item['value'], $item['type']);
            $text = substr_replace($text, $masked, $item['position'], $item['length']);
        }

        return $text;
    }

    /**
     * Mascara dados sensíveis em um array recursivamente
     */
    public function maskArray(array $data): array
    {
        $result = [];

        foreach ($data as $key => $value) {
            // Verifica se a chave indica dado sensível
            $sensitiveKey = $this->isSensitiveKey($key);

            if (is_array($value)) {
                $result[$key] = $this->maskArray($value);
            } elseif (is_string($value)) {
                if ($sensitiveKey) {
                    $result[$key] = $this->maskByKeyType($value, $key);
                } else {
                    $result[$key] = $this->maskString($value);
                }
            } else {
                $result[$key] = $value;
            }
        }

        return $result;
    }

    /**
     * Remove completamente dados sensíveis
     */
    public function redact(string $text): string
    {
        $detected = $this->detector->scanDetailed($text);

        // Processa do fim para o início
        $detected = array_reverse($detected);

        foreach ($detected as $item) {
            $text = substr_replace($text, $this->redactText, $item['position'], $item['length']);
        }

        return $text;
    }

    /**
     * Mascara valor baseado no tipo
     */
    public function maskValue(string $value, string $type): string
    {
        return match ($type) {
            'cpf' => $this->maskCpf($value),
            'cnpj' => $this->maskCnpj($value),
            'email' => $this->maskEmail($value),
            'phone' => $this->maskPhone($value),
            'credit_card' => $this->maskCreditCard($value),
            'pix' => $this->maskPix($value),
            default => $this->maskGeneric($value),
        };
    }

    /**
     * Mascara CPF: 123.456.789-00 → ***.456.789-**
     */
    public function maskCpf(string $cpf): string
    {
        $clean = preg_replace('/\D/', '', $cpf);

        if (strlen($clean) !== 11) {
            return $this->maskGeneric($cpf);
        }

        // Mantém dígitos do meio visíveis
        $masked = str_repeat($this->maskChar, 3) . '.' .
                  substr($clean, 3, 3) . '.' .
                  substr($clean, 6, 3) . '-' .
                  str_repeat($this->maskChar, 2);

        return $masked;
    }

    /**
     * Mascara CNPJ: 12.345.678/0001-00 → **.345.678/****-**
     */
    public function maskCnpj(string $cnpj): string
    {
        $clean = preg_replace('/\D/', '', $cnpj);

        if (strlen($clean) !== 14) {
            return $this->maskGeneric($cnpj);
        }

        $masked = str_repeat($this->maskChar, 2) . '.' .
                  substr($clean, 2, 3) . '.' .
                  substr($clean, 5, 3) . '/' .
                  str_repeat($this->maskChar, 4) . '-' .
                  str_repeat($this->maskChar, 2);

        return $masked;
    }

    /**
     * Mascara email: joao.silva@email.com → j***.s****@e****.com
     */
    public function maskEmail(string $email): string
    {
        $parts = explode('@', $email);

        if (count($parts) !== 2) {
            return $this->maskGeneric($email);
        }

        [$local, $domain] = $parts;
        $domainParts = explode('.', $domain);

        // Mascara parte local
        $maskedLocal = $this->maskKeepFirst($local, 1);

        // Mascara domínio (mantém TLD)
        if (count($domainParts) >= 2) {
            $tld = array_pop($domainParts);
            $domainName = implode('.', $domainParts);
            $maskedDomain = $this->maskKeepFirst($domainName, 1) . '.' . $tld;
        } else {
            $maskedDomain = $this->maskKeepFirst($domain, 1);
        }

        return $maskedLocal . '@' . $maskedDomain;
    }

    /**
     * Mascara telefone: (11) 99999-9999 → (11) *****-9999
     */
    public function maskPhone(string $phone): string
    {
        $clean = preg_replace('/\D/', '', $phone);

        if (strlen($clean) < 10) {
            return $this->maskGeneric($phone);
        }

        // Mantém DDD e últimos 4 dígitos
        $ddd = substr($clean, 0, 2);
        $last4 = substr($clean, -4);
        $middleLength = strlen($clean) - 6;

        return '(' . $ddd . ') ' . str_repeat($this->maskChar, $middleLength) . '-' . $last4;
    }

    /**
     * Mascara cartão de crédito: 1234 5678 9012 3456 → **** **** **** 3456
     */
    public function maskCreditCard(string $card): string
    {
        $clean = preg_replace('/\D/', '', $card);

        if (strlen($clean) < 13 || strlen($clean) > 19) {
            return $this->maskGeneric($card);
        }

        $last4 = substr($clean, -4);
        $prefix = str_repeat($this->maskChar . $this->maskChar . $this->maskChar . $this->maskChar . ' ', 3);

        return trim($prefix) . ' ' . $last4;
    }

    /**
     * Mascara chave PIX aleatória
     */
    public function maskPix(string $pix): string
    {
        // Mantém primeiros e últimos 4 caracteres
        if (strlen($pix) > 12) {
            return substr($pix, 0, 4) .
                   str_repeat($this->maskChar, strlen($pix) - 8) .
                   substr($pix, -4);
        }

        return $this->maskGeneric($pix);
    }

    /**
     * Mascaramento genérico - mantém 25% visível
     */
    public function maskGeneric(string $value): string
    {
        $length = strlen($value);

        if ($length <= 4) {
            return str_repeat($this->maskChar, $length);
        }

        $visible = max(1, (int) ceil($length * 0.25));
        $masked = $length - $visible;

        return substr($value, 0, $visible) . str_repeat($this->maskChar, $masked);
    }

    /**
     * Mascara mantendo N primeiros caracteres
     */
    private function maskKeepFirst(string $value, int $keep): string
    {
        if (strlen($value) <= $keep) {
            return str_repeat($this->maskChar, strlen($value));
        }

        return substr($value, 0, $keep) . str_repeat($this->maskChar, strlen($value) - $keep);
    }

    /**
     * Verifica se chave indica dado sensível
     */
    private function isSensitiveKey(string $key): bool
    {
        $sensitiveKeys = [
            'cpf', 'cnpj', 'email', 'phone', 'telefone', 'celular',
            'password', 'senha', 'secret', 'token', 'api_key', 'apikey',
            'credit_card', 'cartao', 'card_number', 'cvv', 'cvc',
            'pix', 'pix_key', 'chave_pix',
            'name', 'nome', 'full_name', 'nome_completo',
            'address', 'endereco', 'cep', 'rg', 'passport',
            'birth_date', 'data_nascimento', 'birthday',
        ];

        $keyLower = strtolower($key);

        foreach ($sensitiveKeys as $sensitive) {
            if (str_contains($keyLower, $sensitive)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Mascara baseado no tipo inferido pela chave
     */
    private function maskByKeyType(string $value, string $key): string
    {
        $keyLower = strtolower($key);

        if (str_contains($keyLower, 'cpf')) {
            return $this->maskCpf($value);
        }

        if (str_contains($keyLower, 'cnpj')) {
            return $this->maskCnpj($value);
        }

        if (str_contains($keyLower, 'email')) {
            return $this->maskEmail($value);
        }

        if (str_contains($keyLower, 'phone') || str_contains($keyLower, 'telefone') || str_contains($keyLower, 'celular')) {
            return $this->maskPhone($value);
        }

        if (str_contains($keyLower, 'card') || str_contains($keyLower, 'cartao')) {
            return $this->maskCreditCard($value);
        }

        if (str_contains($keyLower, 'pix')) {
            return $this->maskPix($value);
        }

        // Para senhas e tokens, mascara completamente
        if (str_contains($keyLower, 'password') || str_contains($keyLower, 'senha') ||
            str_contains($keyLower, 'secret') || str_contains($keyLower, 'token')) {
            return str_repeat($this->maskChar, min(8, strlen($value)));
        }

        return $this->maskGeneric($value);
    }
}

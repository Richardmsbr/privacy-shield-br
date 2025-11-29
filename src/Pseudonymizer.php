<?php

declare(strict_types=1);

namespace PrivacyShield;

use PrivacyShield\Detectors\Detector;

/**
 * Pseudonimizador de dados
 *
 * Substitui dados reais por dados falsos consistentes.
 * Mesmo input + seed = mesmo output (útil para FKs em banco de dados).
 */
class Pseudonymizer
{
    private array $config;
    private Detector $detector;
    private array $cache = [];

    // Nomes brasileiros comuns
    private array $firstNames = [
        'Ana', 'Maria', 'João', 'Pedro', 'Lucas', 'Marcos', 'Paulo', 'Carlos',
        'Julia', 'Fernanda', 'Rafael', 'Gabriel', 'Beatriz', 'Larissa', 'Bruno',
        'Thiago', 'Amanda', 'Juliana', 'Roberto', 'Ricardo', 'Camila', 'Leticia',
        'Felipe', 'Gustavo', 'Isabela', 'Mariana', 'Diego', 'Rodrigo', 'Patricia',
        'Renata', 'Leonardo', 'Mateus', 'Natalia', 'Vanessa', 'Eduardo', 'Andre',
    ];

    private array $lastNames = [
        'Silva', 'Santos', 'Oliveira', 'Souza', 'Rodrigues', 'Ferreira', 'Alves',
        'Pereira', 'Lima', 'Gomes', 'Costa', 'Ribeiro', 'Martins', 'Carvalho',
        'Almeida', 'Lopes', 'Soares', 'Fernandes', 'Vieira', 'Barbosa', 'Rocha',
        'Dias', 'Nascimento', 'Andrade', 'Moreira', 'Nunes', 'Marques', 'Machado',
        'Mendes', 'Freitas', 'Cardoso', 'Ramos', 'Gonçalves', 'Santana', 'Teixeira',
    ];

    private array $emailDomains = [
        'email.com', 'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com.br',
        'uol.com.br', 'terra.com.br', 'bol.com.br', 'ig.com.br', 'globo.com',
    ];

    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->detector = new Detector($config);
    }

    /**
     * Pseudonimiza dados
     *
     * @param string|array|object $data Dados originais
     * @param string|null $seed Seed para consistência
     */
    public function process(string|array|object $data, ?string $seed = null): string|array
    {
        if (is_object($data)) {
            $data = (array) $data;
        }

        if (is_string($data)) {
            return $this->pseudonymizeString($data, $seed);
        }

        return $this->pseudonymizeArray($data, $seed);
    }

    /**
     * Pseudonimiza string substituindo dados detectados
     */
    private function pseudonymizeString(string $text, ?string $seed = null): string
    {
        $detected = $this->detector->scanDetailed($text);

        // Processa do fim para o início
        $detected = array_reverse($detected);

        foreach ($detected as $item) {
            $fake = $this->generateFake($item['type'], $item['value'], $seed);
            $text = substr_replace($text, $fake, $item['position'], $item['length']);
        }

        return $text;
    }

    /**
     * Pseudonimiza array recursivamente
     */
    private function pseudonymizeArray(array $data, ?string $seed = null): array
    {
        $result = [];

        foreach ($data as $key => $value) {
            $itemSeed = $seed ? $seed . '.' . $key : (string) $key;

            if (is_array($value)) {
                $result[$key] = $this->pseudonymizeArray($value, $itemSeed);
            } elseif (is_string($value)) {
                $result[$key] = $this->pseudonymizeByKey($value, $key, $itemSeed);
            } else {
                $result[$key] = $value;
            }
        }

        return $result;
    }

    /**
     * Pseudonimiza valor baseado na chave do array
     */
    private function pseudonymizeByKey(string $value, string $key, string $seed): string
    {
        $keyLower = strtolower($key);

        // Detecta tipo pela chave
        if (str_contains($keyLower, 'cpf')) {
            return $this->generateFakeCpf($seed);
        }

        if (str_contains($keyLower, 'cnpj')) {
            return $this->generateFakeCnpj($seed);
        }

        if (str_contains($keyLower, 'email')) {
            return $this->generateFakeEmail($seed);
        }

        if (str_contains($keyLower, 'phone') || str_contains($keyLower, 'telefone') || str_contains($keyLower, 'celular')) {
            return $this->generateFakePhone($seed);
        }

        if (str_contains($keyLower, 'name') || str_contains($keyLower, 'nome')) {
            return $this->generateFakeName($seed);
        }

        // Tenta detectar no valor
        return $this->pseudonymizeString($value, $seed);
    }

    /**
     * Gera dado falso baseado no tipo
     */
    private function generateFake(string $type, string $original, ?string $seed = null): string
    {
        $effectiveSeed = $seed ?? $original;

        return match ($type) {
            'cpf' => $this->generateFakeCpf($effectiveSeed),
            'cnpj' => $this->generateFakeCnpj($effectiveSeed),
            'email' => $this->generateFakeEmail($effectiveSeed),
            'phone' => $this->generateFakePhone($effectiveSeed),
            'credit_card' => $this->generateFakeCreditCard($effectiveSeed),
            'pix' => $this->generateFakePix($effectiveSeed),
            default => $this->generateFakeGeneric($original, $effectiveSeed),
        };
    }

    /**
     * Gera CPF falso válido (passa na validação)
     */
    public function generateFakeCpf(?string $seed = null): string
    {
        $hash = $this->seedToHash($seed ?? uniqid());

        // Usa hash para gerar 9 primeiros dígitos
        $cpf = '';
        for ($i = 0; $i < 9; $i++) {
            $cpf .= (int) (hexdec($hash[$i]) % 10);
        }

        // Calcula dígitos verificadores
        $cpf .= $this->calculateCpfDigit($cpf);
        $cpf .= $this->calculateCpfDigit($cpf);

        // Formata
        return substr($cpf, 0, 3) . '.' .
               substr($cpf, 3, 3) . '.' .
               substr($cpf, 6, 3) . '-' .
               substr($cpf, 9, 2);
    }

    /**
     * Gera CNPJ falso válido
     */
    public function generateFakeCnpj(?string $seed = null): string
    {
        $hash = $this->seedToHash($seed ?? uniqid());

        // Usa hash para gerar 8 primeiros dígitos + 0001 (filial)
        $cnpj = '';
        for ($i = 0; $i < 8; $i++) {
            $cnpj .= (int) (hexdec($hash[$i]) % 10);
        }
        $cnpj .= '0001';

        // Calcula dígitos verificadores
        $cnpj .= $this->calculateCnpjDigit($cnpj, [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
        $cnpj .= $this->calculateCnpjDigit($cnpj, [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);

        // Formata
        return substr($cnpj, 0, 2) . '.' .
               substr($cnpj, 2, 3) . '.' .
               substr($cnpj, 5, 3) . '/' .
               substr($cnpj, 8, 4) . '-' .
               substr($cnpj, 12, 2);
    }

    /**
     * Gera email falso
     */
    public function generateFakeEmail(?string $seed = null): string
    {
        $hash = $this->seedToHash($seed ?? uniqid());
        $hashNum = hexdec(substr($hash, 0, 8));

        $firstName = $this->firstNames[$hashNum % count($this->firstNames)];
        $lastName = $this->lastNames[($hashNum >> 8) % count($this->lastNames)];
        $domain = $this->emailDomains[($hashNum >> 16) % count($this->emailDomains)];
        $number = ($hashNum % 99) + 1;

        $firstName = $this->removeAccents(strtolower($firstName));
        $lastName = $this->removeAccents(strtolower($lastName));

        return "{$firstName}.{$lastName}{$number}@{$domain}";
    }

    /**
     * Gera telefone falso
     */
    public function generateFakePhone(?string $seed = null): string
    {
        $hash = $this->seedToHash($seed ?? uniqid());
        $hashNum = hexdec(substr($hash, 0, 8));

        // DDDs válidos de São Paulo e outras capitais
        $ddds = [11, 21, 31, 41, 51, 61, 71, 81, 85, 92];
        $ddd = $ddds[$hashNum % count($ddds)];

        // Número de celular (começa com 9)
        $number = 9 . str_pad((string) ($hashNum % 10000000), 7, '0', STR_PAD_LEFT);
        $part1 = substr($number, 0, 5);
        $part2 = substr($number, 5, 4);

        return "({$ddd}) {$part1}-{$part2}";
    }

    /**
     * Gera número de cartão falso (formato válido, não funcional)
     */
    public function generateFakeCreditCard(?string $seed = null): string
    {
        $hash = $this->seedToHash($seed ?? uniqid());

        // Prefixo Visa teste
        $card = '4';
        for ($i = 0; $i < 14; $i++) {
            $card .= (int) (hexdec($hash[$i]) % 10);
        }

        // Calcula dígito Luhn
        $card .= $this->calculateLuhnDigit($card);

        // Formata
        return chunk_split($card, 4, ' ');
    }

    /**
     * Gera chave PIX aleatória falsa
     */
    public function generateFakePix(?string $seed = null): string
    {
        $hash = $this->seedToHash($seed ?? uniqid());

        return substr($hash, 0, 8) . '-' .
               substr($hash, 8, 4) . '-' .
               substr($hash, 12, 4) . '-' .
               substr($hash, 16, 4) . '-' .
               substr($hash, 20, 12);
    }

    /**
     * Gera nome completo falso
     */
    public function generateFakeName(?string $seed = null): string
    {
        $hash = $this->seedToHash($seed ?? uniqid());
        $hashNum = hexdec(substr($hash, 0, 8));

        $firstName = $this->firstNames[$hashNum % count($this->firstNames)];
        $lastName = $this->lastNames[($hashNum >> 8) % count($this->lastNames)];

        return "{$firstName} {$lastName}";
    }

    /**
     * Gera dado genérico mantendo formato similar
     */
    private function generateFakeGeneric(string $original, string $seed): string
    {
        $hash = $this->seedToHash($seed);
        $result = '';
        $hashIndex = 0;

        for ($i = 0; $i < strlen($original); $i++) {
            $char = $original[$i];

            if (ctype_alpha($char)) {
                $base = ctype_upper($char) ? 'A' : 'a';
                $result .= chr(ord($base) + (hexdec($hash[$hashIndex % 32]) % 26));
                $hashIndex++;
            } elseif (ctype_digit($char)) {
                $result .= hexdec($hash[$hashIndex % 32]) % 10;
                $hashIndex++;
            } else {
                $result .= $char;
            }
        }

        return $result;
    }

    /**
     * Converte seed em hash consistente
     */
    private function seedToHash(string $seed): string
    {
        if (isset($this->cache[$seed])) {
            return $this->cache[$seed];
        }

        $hash = hash('sha256', $seed);
        $this->cache[$seed] = $hash;

        return $hash;
    }

    /**
     * Calcula dígito verificador do CPF
     */
    private function calculateCpfDigit(string $cpf): int
    {
        $length = strlen($cpf);
        $sum = 0;

        for ($i = 0; $i < $length; $i++) {
            $sum += (int) $cpf[$i] * (($length + 1) - $i);
        }

        $remainder = $sum % 11;

        return $remainder < 2 ? 0 : 11 - $remainder;
    }

    /**
     * Calcula dígito verificador do CNPJ
     */
    private function calculateCnpjDigit(string $cnpj, array $weights): int
    {
        $sum = 0;

        for ($i = 0; $i < count($weights); $i++) {
            $sum += (int) $cnpj[$i] * $weights[$i];
        }

        $remainder = $sum % 11;

        return $remainder < 2 ? 0 : 11 - $remainder;
    }

    /**
     * Calcula dígito Luhn para cartão de crédito
     */
    private function calculateLuhnDigit(string $number): int
    {
        $sum = 0;
        $length = strlen($number);

        for ($i = 0; $i < $length; $i++) {
            $digit = (int) $number[$length - 1 - $i];

            if ($i % 2 === 0) {
                $digit *= 2;
                if ($digit > 9) {
                    $digit -= 9;
                }
            }

            $sum += $digit;
        }

        return (10 - ($sum % 10)) % 10;
    }

    /**
     * Remove acentos de string
     */
    private function removeAccents(string $string): string
    {
        $accents = [
            'á' => 'a', 'à' => 'a', 'ã' => 'a', 'â' => 'a', 'ä' => 'a',
            'é' => 'e', 'è' => 'e', 'ê' => 'e', 'ë' => 'e',
            'í' => 'i', 'ì' => 'i', 'î' => 'i', 'ï' => 'i',
            'ó' => 'o', 'ò' => 'o', 'õ' => 'o', 'ô' => 'o', 'ö' => 'o',
            'ú' => 'u', 'ù' => 'u', 'û' => 'u', 'ü' => 'u',
            'ç' => 'c', 'ñ' => 'n',
        ];

        return strtr($string, $accents);
    }

    /**
     * Limpa cache de seeds
     */
    public function clearCache(): void
    {
        $this->cache = [];
    }
}

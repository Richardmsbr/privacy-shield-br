<?php

declare(strict_types=1);

namespace PrivacyShield\Detectors;

/**
 * Detector de dados pessoais sensíveis
 *
 * Identifica automaticamente CPF, CNPJ, email, telefone, PIX, cartão de crédito
 * em strings de texto. Otimizado para dados brasileiros.
 */
class Detector
{
    private array $config;
    private array $patterns;

    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->patterns = $this->buildPatterns();
    }

    /**
     * Escaneia texto e retorna contagem de dados sensíveis
     *
     * @return array ['cpf' => 2, 'email' => 1, 'total' => 3]
     */
    public function scan(string $text): array
    {
        $results = [
            'cpf' => 0,
            'cnpj' => 0,
            'email' => 0,
            'phone' => 0,
            'pix' => 0,
            'credit_card' => 0,
            'total' => 0,
        ];

        foreach ($this->patterns as $type => $pattern) {
            if ($this->isDetectorEnabled($type)) {
                $matches = [];
                preg_match_all($pattern, $text, $matches);
                $count = count($matches[0]);

                // Validação adicional para CPF/CNPJ
                if ($type === 'cpf') {
                    $count = $this->countValidCpfs($matches[0]);
                } elseif ($type === 'cnpj') {
                    $count = $this->countValidCnpjs($matches[0]);
                }

                $results[$type] = $count;
                $results['total'] += $count;
            }
        }

        return $results;
    }

    /**
     * Escaneia texto e retorna detalhes de cada dado encontrado
     *
     * @return array Lista com tipo, valor, posição de cada dado
     */
    public function scanDetailed(string $text): array
    {
        $results = [];

        foreach ($this->patterns as $type => $pattern) {
            if (!$this->isDetectorEnabled($type)) {
                continue;
            }

            $matches = [];
            preg_match_all($pattern, $text, $matches, PREG_OFFSET_CAPTURE);

            foreach ($matches[0] as $match) {
                $value = $match[0];
                $position = $match[1];

                // Validação para CPF
                if ($type === 'cpf' && !$this->isValidCpf($value)) {
                    continue;
                }

                // Validação para CNPJ
                if ($type === 'cnpj' && !$this->isValidCnpj($value)) {
                    continue;
                }

                $results[] = [
                    'type' => $type,
                    'value' => $value,
                    'position' => $position,
                    'length' => strlen($value),
                ];
            }
        }

        // Ordena por posição
        usort($results, fn($a, $b) => $a['position'] <=> $b['position']);

        return $results;
    }

    /**
     * Verifica se texto contém tipo específico de dado
     */
    public function contains(string $text, string $type): bool
    {
        if (!isset($this->patterns[$type])) {
            return false;
        }

        $matches = [];
        preg_match_all($this->patterns[$type], $text, $matches);

        if ($type === 'cpf') {
            return $this->countValidCpfs($matches[0]) > 0;
        }

        if ($type === 'cnpj') {
            return $this->countValidCnpjs($matches[0]) > 0;
        }

        return count($matches[0]) > 0;
    }

    /**
     * Extrai todos os valores de um tipo específico
     */
    public function extract(string $text, string $type): array
    {
        if (!isset($this->patterns[$type])) {
            return [];
        }

        $matches = [];
        preg_match_all($this->patterns[$type], $text, $matches);

        $results = $matches[0];

        // Filtra CPFs válidos
        if ($type === 'cpf') {
            $results = array_filter($results, fn($cpf) => $this->isValidCpf($cpf));
        }

        // Filtra CNPJs válidos
        if ($type === 'cnpj') {
            $results = array_filter($results, fn($cnpj) => $this->isValidCnpj($cnpj));
        }

        return array_values($results);
    }

    /**
     * Padrões regex para cada tipo de dado
     */
    private function buildPatterns(): array
    {
        return [
            // CPF: 000.000.000-00 ou 00000000000
            'cpf' => '/\b\d{3}\.?\d{3}\.?\d{3}[-.]?\d{2}\b/',

            // CNPJ: 00.000.000/0000-00 ou 00000000000000
            'cnpj' => '/\b\d{2}\.?\d{3}\.?\d{3}\/?\d{4}[-.]?\d{2}\b/',

            // Email
            'email' => '/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/',

            // Telefone brasileiro: (11) 99999-9999, 11999999999, +55 11 99999-9999
            'phone' => '/(?:\+55\s?)?(?:\(?\d{2}\)?\s?)?(?:9\s?)?\d{4,5}[-.\s]?\d{4}\b/',

            // PIX: pode ser CPF, CNPJ, email, telefone ou chave aleatória
            // Chave aleatória PIX: 32 caracteres hexadecimais com hífens
            'pix' => '/\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/i',

            // Cartão de crédito: 4 grupos de 4 dígitos
            'credit_card' => '/\b(?:\d{4}[-.\s]?){3}\d{4}\b/',
        ];
    }

    /**
     * Verifica se detector está habilitado na config
     */
    private function isDetectorEnabled(string $type): bool
    {
        return $this->config['detectors'][$type] ?? true;
    }

    /**
     * Conta CPFs válidos em uma lista
     */
    private function countValidCpfs(array $cpfs): int
    {
        return count(array_filter($cpfs, fn($cpf) => $this->isValidCpf($cpf)));
    }

    /**
     * Conta CNPJs válidos em uma lista
     */
    private function countValidCnpjs(array $cnpjs): int
    {
        return count(array_filter($cnpjs, fn($cnpj) => $this->isValidCnpj($cnpj)));
    }

    /**
     * Valida CPF usando algoritmo oficial
     */
    public function isValidCpf(string $cpf): bool
    {
        // Remove formatação
        $cpf = preg_replace('/\D/', '', $cpf);

        // Verifica tamanho
        if (strlen($cpf) !== 11) {
            return false;
        }

        // Verifica CPFs inválidos conhecidos
        if (preg_match('/^(\d)\1{10}$/', $cpf)) {
            return false;
        }

        // Calcula dígitos verificadores
        for ($t = 9; $t < 11; $t++) {
            $sum = 0;
            for ($i = 0; $i < $t; $i++) {
                $sum += (int) $cpf[$i] * (($t + 1) - $i);
            }
            $digit = ((10 * $sum) % 11) % 10;
            if ((int) $cpf[$t] !== $digit) {
                return false;
            }
        }

        return true;
    }

    /**
     * Valida CNPJ usando algoritmo oficial
     */
    public function isValidCnpj(string $cnpj): bool
    {
        // Remove formatação
        $cnpj = preg_replace('/\D/', '', $cnpj);

        // Verifica tamanho
        if (strlen($cnpj) !== 14) {
            return false;
        }

        // Verifica CNPJs inválidos conhecidos
        if (preg_match('/^(\d)\1{13}$/', $cnpj)) {
            return false;
        }

        // Calcula primeiro dígito verificador
        $weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        $sum = 0;
        for ($i = 0; $i < 12; $i++) {
            $sum += (int) $cnpj[$i] * $weights1[$i];
        }
        $digit1 = $sum % 11 < 2 ? 0 : 11 - ($sum % 11);

        if ((int) $cnpj[12] !== $digit1) {
            return false;
        }

        // Calcula segundo dígito verificador
        $weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        $sum = 0;
        for ($i = 0; $i < 13; $i++) {
            $sum += (int) $cnpj[$i] * $weights2[$i];
        }
        $digit2 = $sum % 11 < 2 ? 0 : 11 - ($sum % 11);

        return (int) $cnpj[13] === $digit2;
    }

    /**
     * Retorna todos os padrões disponíveis
     */
    public function getPatterns(): array
    {
        return $this->patterns;
    }

    /**
     * Adiciona padrão customizado
     */
    public function addPattern(string $name, string $pattern): self
    {
        $this->patterns[$name] = $pattern;
        return $this;
    }
}

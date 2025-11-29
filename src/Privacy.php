<?php

declare(strict_types=1);

namespace PrivacyShield;

use PrivacyShield\Detectors\Detector;
use PrivacyShield\Maskers\Masker;
use PrivacyShield\Pseudonymizer;

/**
 * Privacy Shield - Biblioteca de proteção de dados pessoais
 *
 * Detecta, mascara e anonimiza dados sensíveis em conformidade com LGPD/GDPR.
 * Suporte nativo para dados brasileiros: CPF, CNPJ, PIX, telefone.
 *
 * @author Richard <richard@provise.com.br>
 * @license MIT
 */
class Privacy
{
    private Detector $detector;
    private Masker $masker;
    private Pseudonymizer $pseudonymizer;
    private array $config;

    public function __construct(array $config = [])
    {
        $this->config = array_merge($this->defaultConfig(), $config);
        $this->detector = new Detector($this->config);
        $this->masker = new Masker($this->config);
        $this->pseudonymizer = new Pseudonymizer($this->config);
    }

    /**
     * Mascara dados sensíveis em uma string ou array
     *
     * @param string|array|object $data Dados a serem mascarados
     * @return string|array Dados com informações sensíveis mascaradas
     *
     * @example
     * Privacy::mask("Meu CPF é 123.456.789-00")
     * // Retorna: "Meu CPF é ***.***.789-**"
     */
    public static function mask(string|array|object $data): string|array
    {
        $instance = new self();
        return $instance->maskData($data);
    }

    /**
     * Detecta dados sensíveis em uma string
     *
     * @param string $text Texto para análise
     * @return array Lista de dados sensíveis encontrados
     *
     * @example
     * Privacy::scan("Email: joao@email.com, CPF: 123.456.789-00")
     * // Retorna: ['cpf' => 1, 'email' => 1, 'total' => 2]
     */
    public static function scan(string $text): array
    {
        $instance = new self();
        return $instance->detector->scan($text);
    }

    /**
     * Detecta dados sensíveis com detalhes (posição, valor original)
     *
     * @param string $text Texto para análise
     * @return array Lista detalhada de dados sensíveis
     */
    public static function scanDetailed(string $text): array
    {
        $instance = new self();
        return $instance->detector->scanDetailed($text);
    }

    /**
     * Pseudonimiza dados (substitui por dados falsos consistentes)
     *
     * @param string|array|object $data Dados originais
     * @param string|null $seed Seed para consistência (mesmo seed = mesmo resultado)
     * @return string|array Dados pseudonimizados
     *
     * @example
     * Privacy::pseudonymize(['name' => 'João Silva', 'cpf' => '123.456.789-00'])
     * // Retorna: ['name' => 'Maria Santos', 'cpf' => '987.654.321-00']
     */
    public static function pseudonymize(string|array|object $data, ?string $seed = null): string|array
    {
        $instance = new self();
        return $instance->pseudonymizer->process($data, $seed);
    }

    /**
     * Verifica se uma string contém dados sensíveis
     *
     * @param string $text Texto para verificação
     * @return bool True se contém dados sensíveis
     */
    public static function hasSensitiveData(string $text): bool
    {
        $instance = new self();
        $result = $instance->detector->scan($text);
        return $result['total'] > 0;
    }

    /**
     * Remove completamente dados sensíveis (substitui por [REMOVIDO])
     *
     * @param string $text Texto original
     * @return string Texto limpo
     */
    public static function redact(string $text): string
    {
        $instance = new self();
        return $instance->masker->redact($text);
    }

    /**
     * Mascara dados de forma interna (não estático)
     */
    public function maskData(string|array|object $data): string|array
    {
        if (is_string($data)) {
            return $this->masker->maskString($data);
        }

        if (is_object($data)) {
            $data = (array) $data;
        }

        return $this->masker->maskArray($data);
    }

    /**
     * Configuração padrão
     */
    private function defaultConfig(): array
    {
        return [
            'mask_char' => '*',
            'mask_email_domain' => true,
            'mask_keep_length' => false,
            'detectors' => [
                'cpf' => true,
                'cnpj' => true,
                'email' => true,
                'phone' => true,
                'pix' => true,
                'credit_card' => true,
                'name' => false, // Requer NLP, desabilitado por padrão
            ],
            'redact_text' => '[REMOVIDO]',
            'locale' => 'pt_BR',
        ];
    }

    /**
     * Retorna instância do Detector
     */
    public function getDetector(): Detector
    {
        return $this->detector;
    }

    /**
     * Retorna instância do Masker
     */
    public function getMasker(): Masker
    {
        return $this->masker;
    }

    /**
     * Retorna instância do Pseudonymizer
     */
    public function getPseudonymizer(): Pseudonymizer
    {
        return $this->pseudonymizer;
    }
}

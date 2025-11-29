<?php

declare(strict_types=1);

namespace PrivacyShield\Tests;

use PHPUnit\Framework\TestCase;
use PrivacyShield\Pseudonymizer;
use PrivacyShield\Detectors\Detector;

class PseudonymizerTest extends TestCase
{
    private Pseudonymizer $pseudonymizer;
    private Detector $detector;

    protected function setUp(): void
    {
        $this->pseudonymizer = new Pseudonymizer();
        $this->detector = new Detector();
    }

    // ==================== CPF Generation ====================

    public function testGeneratesValidCpf(): void
    {
        $cpf = $this->pseudonymizer->generateFakeCpf('test_seed');

        // Remove formatação e valida
        $this->assertTrue($this->detector->isValidCpf($cpf));
    }

    public function testGeneratesConsistentCpf(): void
    {
        $cpf1 = $this->pseudonymizer->generateFakeCpf('same_seed');
        $cpf2 = $this->pseudonymizer->generateFakeCpf('same_seed');

        $this->assertEquals($cpf1, $cpf2);
    }

    public function testGeneratesDifferentCpfWithDifferentSeed(): void
    {
        $cpf1 = $this->pseudonymizer->generateFakeCpf('seed_1');
        $cpf2 = $this->pseudonymizer->generateFakeCpf('seed_2');

        $this->assertNotEquals($cpf1, $cpf2);
    }

    // ==================== CNPJ Generation ====================

    public function testGeneratesValidCnpj(): void
    {
        $cnpj = $this->pseudonymizer->generateFakeCnpj('test_seed');

        $this->assertTrue($this->detector->isValidCnpj($cnpj));
    }

    public function testGeneratesConsistentCnpj(): void
    {
        $cnpj1 = $this->pseudonymizer->generateFakeCnpj('same_seed');
        $cnpj2 = $this->pseudonymizer->generateFakeCnpj('same_seed');

        $this->assertEquals($cnpj1, $cnpj2);
    }

    // ==================== Email Generation ====================

    public function testGeneratesValidEmail(): void
    {
        $email = $this->pseudonymizer->generateFakeEmail('test_seed');

        $this->assertStringContainsString('@', $email);
        $this->assertMatchesRegularExpression('/^[a-z]+\.[a-z]+\d+@[a-z.]+$/', $email);
    }

    public function testGeneratesConsistentEmail(): void
    {
        $email1 = $this->pseudonymizer->generateFakeEmail('same_seed');
        $email2 = $this->pseudonymizer->generateFakeEmail('same_seed');

        $this->assertEquals($email1, $email2);
    }

    // ==================== Phone Generation ====================

    public function testGeneratesValidPhone(): void
    {
        $phone = $this->pseudonymizer->generateFakePhone('test_seed');

        $this->assertMatchesRegularExpression('/^\(\d{2}\) 9\d{4}-\d{4}$/', $phone);
    }

    // ==================== Name Generation ====================

    public function testGeneratesName(): void
    {
        $name = $this->pseudonymizer->generateFakeName('test_seed');

        $this->assertNotEmpty($name);
        $this->assertStringContainsString(' ', $name); // Tem nome e sobrenome
    }

    // ==================== Credit Card Generation ====================

    public function testGeneratesCreditCard(): void
    {
        $card = $this->pseudonymizer->generateFakeCreditCard('test_seed');

        // Formato com espaços
        $this->assertMatchesRegularExpression('/^\d{4}\s\d{4}\s\d{4}\s\d{4}\s?$/', $card);
    }

    // ==================== PIX Generation ====================

    public function testGeneratesPixKey(): void
    {
        $pix = $this->pseudonymizer->generateFakePix('test_seed');

        // Formato UUID-like
        $this->assertMatchesRegularExpression('/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/', $pix);
    }

    // ==================== Process Array ====================

    public function testProcessesArray(): void
    {
        $data = [
            'cpf' => '529.982.247-25',
            'email' => 'original@email.com',
        ];

        $result = $this->pseudonymizer->process($data, 'test_seed');

        // Valores devem ser diferentes dos originais
        $this->assertNotEquals('529.982.247-25', $result['cpf']);
        $this->assertNotEquals('original@email.com', $result['email']);

        // CPF gerado deve ser válido
        $this->assertTrue($this->detector->isValidCpf($result['cpf']));
    }

    public function testProcessesNestedArray(): void
    {
        $data = [
            'usuario' => [
                'cpf' => '529.982.247-25',
            ],
        ];

        $result = $this->pseudonymizer->process($data, 'test_seed');

        $this->assertNotEquals('529.982.247-25', $result['usuario']['cpf']);
    }

    // ==================== Process String ====================

    public function testProcessesString(): void
    {
        $text = "CPF: 529.982.247-25";
        $result = $this->pseudonymizer->process($text, 'test_seed');

        $this->assertStringNotContainsString('529.982.247-25', $result);
        $this->assertStringContainsString('CPF:', $result);
    }

    // ==================== Consistency ====================

    public function testMaintainsConsistencyAcrossMultipleCalls(): void
    {
        $data = ['cpf' => '529.982.247-25'];

        $result1 = $this->pseudonymizer->process($data, 'user_123');
        $result2 = $this->pseudonymizer->process($data, 'user_123');

        $this->assertEquals($result1['cpf'], $result2['cpf']);
    }
}

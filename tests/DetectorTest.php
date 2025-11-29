<?php

declare(strict_types=1);

namespace PrivacyShield\Tests;

use PHPUnit\Framework\TestCase;
use PrivacyShield\Detectors\Detector;

class DetectorTest extends TestCase
{
    private Detector $detector;

    protected function setUp(): void
    {
        $this->detector = new Detector();
    }

    // ==================== CPF Tests ====================

    public function testDetectsCpfWithMask(): void
    {
        $text = "Meu CPF é 529.982.247-25";
        $result = $this->detector->scan($text);

        $this->assertEquals(1, $result['cpf']);
    }

    public function testDetectsCpfWithoutMask(): void
    {
        $text = "CPF: 52998224725";
        $result = $this->detector->scan($text);

        $this->assertEquals(1, $result['cpf']);
    }

    public function testRejectsInvalidCpf(): void
    {
        // CPF com dígitos verificadores errados
        $text = "CPF inválido: 123.456.789-00";
        $result = $this->detector->scan($text);

        $this->assertEquals(0, $result['cpf']);
    }

    public function testRejectsSequentialCpf(): void
    {
        $text = "CPF sequencial: 111.111.111-11";
        $result = $this->detector->scan($text);

        $this->assertEquals(0, $result['cpf']);
    }

    public function testValidateCpfMethod(): void
    {
        // CPFs válidos conhecidos
        $this->assertTrue($this->detector->isValidCpf('529.982.247-25'));
        $this->assertTrue($this->detector->isValidCpf('52998224725'));

        // CPFs inválidos
        $this->assertFalse($this->detector->isValidCpf('123.456.789-00'));
        $this->assertFalse($this->detector->isValidCpf('111.111.111-11'));
        $this->assertFalse($this->detector->isValidCpf('12345678'));
    }

    // ==================== CNPJ Tests ====================

    public function testDetectsCnpjWithMask(): void
    {
        $text = "CNPJ: 11.222.333/0001-81";
        $result = $this->detector->scan($text);

        $this->assertEquals(1, $result['cnpj']);
    }

    public function testDetectsCnpjWithoutMask(): void
    {
        $text = "CNPJ: 11222333000181";
        $result = $this->detector->scan($text);

        $this->assertEquals(1, $result['cnpj']);
    }

    public function testRejectsInvalidCnpj(): void
    {
        $text = "CNPJ inválido: 11.222.333/0001-00";
        $result = $this->detector->scan($text);

        $this->assertEquals(0, $result['cnpj']);
    }

    public function testValidateCnpjMethod(): void
    {
        $this->assertTrue($this->detector->isValidCnpj('11.222.333/0001-81'));
        $this->assertFalse($this->detector->isValidCnpj('11.111.111/1111-11'));
    }

    // ==================== Email Tests ====================

    public function testDetectsEmail(): void
    {
        $text = "Contato: joao.silva@empresa.com.br";
        $result = $this->detector->scan($text);

        $this->assertEquals(1, $result['email']);
    }

    public function testDetectsMultipleEmails(): void
    {
        $text = "Emails: a@a.com, b@b.com, c@c.com";
        $result = $this->detector->scan($text);

        $this->assertEquals(3, $result['email']);
    }

    // ==================== Phone Tests ====================

    public function testDetectsPhoneWithDdd(): void
    {
        $text = "Telefone: (11) 99999-8888";
        $result = $this->detector->scan($text);

        $this->assertEquals(1, $result['phone']);
    }

    public function testDetectsPhoneWithoutMask(): void
    {
        $text = "Tel: 11999998888";
        $result = $this->detector->scan($text);

        $this->assertEquals(1, $result['phone']);
    }

    // ==================== Credit Card Tests ====================

    public function testDetectsCreditCard(): void
    {
        $text = "Cartão: 4111 1111 1111 1111";
        $result = $this->detector->scan($text);

        $this->assertEquals(1, $result['credit_card']);
    }

    // ==================== PIX Tests ====================

    public function testDetectsPixRandomKey(): void
    {
        $text = "Chave PIX: a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        $result = $this->detector->scan($text);

        $this->assertEquals(1, $result['pix']);
    }

    // ==================== Multiple Types ====================

    public function testDetectsMultipleTypes(): void
    {
        $text = "CPF: 529.982.247-25, Email: teste@email.com, Tel: (11) 99999-8888";
        $result = $this->detector->scan($text);

        $this->assertEquals(1, $result['cpf']);
        $this->assertEquals(1, $result['email']);
        $this->assertEquals(1, $result['phone']);
        $this->assertEquals(3, $result['total']);
    }

    // ==================== Detailed Scan ====================

    public function testScanDetailedReturnsPositions(): void
    {
        $text = "CPF: 529.982.247-25";
        $result = $this->detector->scanDetailed($text);

        $this->assertCount(1, $result);
        $this->assertEquals('cpf', $result[0]['type']);
        $this->assertEquals('529.982.247-25', $result[0]['value']);
        $this->assertEquals(5, $result[0]['position']);
    }

    // ==================== Extract ====================

    public function testExtractReturnsValues(): void
    {
        $text = "CPFs: 529.982.247-25 e 111.444.777-35";
        $result = $this->detector->extract($text, 'cpf');

        $this->assertCount(2, $result);
        $this->assertContains('529.982.247-25', $result);
        $this->assertContains('111.444.777-35', $result);
    }

    // ==================== Contains ====================

    public function testContainsReturnsTrueWhenFound(): void
    {
        $text = "Email: teste@email.com";

        $this->assertTrue($this->detector->contains($text, 'email'));
        $this->assertFalse($this->detector->contains($text, 'cpf'));
    }
}

<?php

declare(strict_types=1);

namespace PrivacyShield\Tests;

use PHPUnit\Framework\TestCase;
use PrivacyShield\Maskers\Masker;

class MaskerTest extends TestCase
{
    private Masker $masker;

    protected function setUp(): void
    {
        $this->masker = new Masker([
            'mask_char' => '*',
            'redact_text' => '[REMOVIDO]',
            'detectors' => [
                'cpf' => true,
                'cnpj' => true,
                'email' => true,
                'phone' => true,
                'pix' => true,
                'credit_card' => true,
            ],
        ]);
    }

    // ==================== CPF Masking ====================

    public function testMasksCpf(): void
    {
        $result = $this->masker->maskCpf('529.982.247-25');

        $this->assertEquals('***.982.247-**', $result);
    }

    public function testMasksCpfWithoutFormatting(): void
    {
        $result = $this->masker->maskCpf('52998224725');

        $this->assertEquals('***.982.247-**', $result);
    }

    // ==================== CNPJ Masking ====================

    public function testMasksCnpj(): void
    {
        $result = $this->masker->maskCnpj('11.222.333/0001-81');

        $this->assertEquals('**.222.333/****-**', $result);
    }

    // ==================== Email Masking ====================

    public function testMasksEmail(): void
    {
        $result = $this->masker->maskEmail('joao.silva@empresa.com.br');

        $this->assertStringStartsWith('j', $result);
        $this->assertStringContainsString('@', $result);
        $this->assertStringContainsString('*', $result);
        $this->assertStringEndsWith('.br', $result);
    }

    public function testMasksSimpleEmail(): void
    {
        $result = $this->masker->maskEmail('teste@email.com');

        $this->assertStringStartsWith('t', $result);
        $this->assertStringEndsWith('.com', $result);
    }

    // ==================== Phone Masking ====================

    public function testMasksPhone(): void
    {
        $result = $this->masker->maskPhone('(11) 99999-8888');

        $this->assertEquals('(11) *****-8888', $result);
    }

    public function testMasksPhoneWithoutFormatting(): void
    {
        $result = $this->masker->maskPhone('11999998888');

        $this->assertStringStartsWith('(11)', $result);
        $this->assertStringEndsWith('-8888', $result);
    }

    // ==================== Credit Card Masking ====================

    public function testMasksCreditCard(): void
    {
        $result = $this->masker->maskCreditCard('4111 1111 1111 1111');

        $this->assertStringEndsWith('1111', trim($result));
        $this->assertStringContainsString('*', $result);
    }

    // ==================== String Masking ====================

    public function testMasksStringWithMultipleData(): void
    {
        $text = "CPF: 529.982.247-25, Email: teste@email.com";
        $result = $this->masker->maskString($text);

        $this->assertStringContainsString('***.982.247-**', $result);
        $this->assertStringNotContainsString('529.982.247-25', $result);
        $this->assertStringNotContainsString('teste@email.com', $result);
    }

    // ==================== Array Masking ====================

    public function testMasksArray(): void
    {
        $data = [
            'nome' => 'João Silva',
            'cpf' => '529.982.247-25',
            'email' => 'joao@email.com',
        ];

        $result = $this->masker->maskArray($data);

        $this->assertEquals('***.982.247-**', $result['cpf']);
        $this->assertStringStartsWith('j', $result['email']);
    }

    public function testMasksNestedArray(): void
    {
        $data = [
            'usuario' => [
                'cpf' => '529.982.247-25',
            ],
        ];

        $result = $this->masker->maskArray($data);

        $this->assertEquals('***.982.247-**', $result['usuario']['cpf']);
    }

    // ==================== Redact ====================

    public function testRedactRemovesCompletely(): void
    {
        $text = "CPF: 529.982.247-25";
        $result = $this->masker->redact($text);

        $this->assertEquals('CPF: [REMOVIDO]', $result);
    }

    // ==================== Generic Masking ====================

    public function testMasksGenericValue(): void
    {
        $result = $this->masker->maskGeneric('abcdefghij');

        $this->assertStringStartsWith('a', $result);
        $this->assertStringContainsString('*', $result);
    }
}

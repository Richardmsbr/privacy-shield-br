<?php

declare(strict_types=1);

namespace PrivacyShield\Tests;

use PHPUnit\Framework\TestCase;
use PrivacyShield\Privacy;

class PrivacyTest extends TestCase
{
    // ==================== Static Methods ====================

    public function testMaskStaticMethod(): void
    {
        $text = "CPF: 529.982.247-25";
        $result = Privacy::mask($text);

        $this->assertStringContainsString('***.982.247-**', $result);
    }

    public function testScanStaticMethod(): void
    {
        $text = "CPF: 529.982.247-25, Email: teste@email.com";
        $result = Privacy::scan($text);

        $this->assertEquals(1, $result['cpf']);
        $this->assertEquals(1, $result['email']);
        $this->assertEquals(2, $result['total']);
    }

    public function testHasSensitiveDataStaticMethod(): void
    {
        $this->assertTrue(Privacy::hasSensitiveData("CPF: 529.982.247-25"));
        $this->assertFalse(Privacy::hasSensitiveData("Texto sem dados pessoais"));
    }

    public function testPseudonymizeStaticMethod(): void
    {
        $data = ['cpf' => '529.982.247-25'];
        $result = Privacy::pseudonymize($data, 'test_seed');

        $this->assertNotEquals('529.982.247-25', $result['cpf']);
    }

    public function testRedactStaticMethod(): void
    {
        $text = "CPF: 529.982.247-25";
        $result = Privacy::redact($text);

        $this->assertEquals('CPF: [REMOVIDO]', $result);
    }

    public function testScanDetailedStaticMethod(): void
    {
        $text = "CPF: 529.982.247-25";
        $result = Privacy::scanDetailed($text);

        $this->assertCount(1, $result);
        $this->assertEquals('cpf', $result[0]['type']);
    }

    // ==================== Array Processing ====================

    public function testMaskArray(): void
    {
        $data = [
            'nome' => 'João Silva',
            'cpf' => '529.982.247-25',
            'email' => 'joao@email.com',
            'telefone' => '(11) 99999-8888',
        ];

        $result = Privacy::mask($data);

        $this->assertEquals('***.982.247-**', $result['cpf']);
        $this->assertStringStartsWith('j', $result['email']);
        $this->assertStringContainsString('*', $result['telefone']);
    }

    public function testMaskNestedArray(): void
    {
        $data = [
            'cliente' => [
                'dados' => [
                    'cpf' => '529.982.247-25',
                ],
            ],
        ];

        $result = Privacy::mask($data);

        $this->assertEquals('***.982.247-**', $result['cliente']['dados']['cpf']);
    }

    // ==================== Object Processing ====================

    public function testMaskObject(): void
    {
        $obj = new \stdClass();
        $obj->cpf = '529.982.247-25';
        $obj->email = 'teste@email.com';

        $result = Privacy::mask($obj);

        $this->assertEquals('***.982.247-**', $result['cpf']);
    }

    // ==================== Edge Cases ====================

    public function testEmptyString(): void
    {
        $result = Privacy::mask('');
        $this->assertEquals('', $result);
    }

    public function testEmptyArray(): void
    {
        $result = Privacy::mask([]);
        $this->assertEquals([], $result);
    }

    public function testStringWithoutSensitiveData(): void
    {
        $text = "Texto normal sem dados pessoais";
        $result = Privacy::mask($text);

        $this->assertEquals($text, $result);
    }

    public function testMultipleSameType(): void
    {
        $text = "CPF1: 529.982.247-25, CPF2: 111.444.777-35";
        $result = Privacy::scan($text);

        $this->assertEquals(2, $result['cpf']);
    }

    // ==================== Real World Scenarios ====================

    public function testLogSanitization(): void
    {
        $logData = [
            'action' => 'user_created',
            'user' => [
                'id' => 123,
                'cpf' => '529.982.247-25',
                'email' => 'usuario@empresa.com',
            ],
            'timestamp' => '2024-01-01 00:00:00',
        ];

        $sanitized = Privacy::mask($logData);

        // ID e timestamp devem permanecer
        $this->assertEquals(123, $sanitized['user']['id']);
        $this->assertEquals('2024-01-01 00:00:00', $sanitized['timestamp']);

        // Dados sensíveis devem estar mascarados
        $this->assertEquals('***.982.247-**', $sanitized['user']['cpf']);
        $this->assertStringNotContainsString('usuario@empresa.com', $sanitized['user']['email']);
    }

    public function testApiResponseMasking(): void
    {
        $response = [
            'success' => true,
            'data' => [
                'cliente' => [
                    'nome' => 'João Silva',
                    'cpf' => '529.982.247-25',
                    'cartao' => '4111 1111 1111 1111',
                ],
            ],
        ];

        $masked = Privacy::mask($response);

        $this->assertTrue($masked['success']);
        $this->assertEquals('***.982.247-**', $masked['data']['cliente']['cpf']);
        $this->assertStringEndsWith('1111', trim($masked['data']['cliente']['cartao']));
    }
}

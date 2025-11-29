# Privacy Shield BR

[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.1-8892BF.svg)](https://php.net/)
[![Laravel](https://img.shields.io/badge/laravel-%3E%3D10.0-FF2D20.svg)](https://laravel.com)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![LGPD](https://img.shields.io/badge/LGPD-Compliant-blue.svg)](#lgpd-compliance)

**Biblioteca PHP para detecção e anonimização de dados pessoais** - LGPD/GDPR compliance.

Detecta e mascara automaticamente **CPF, CNPJ, PIX, email, telefone e cartão de crédito** em strings, arrays e objetos. Otimizada para dados brasileiros.

---

## Por que usar?

- **LGPD Compliance**: Anonimização conforme Lei Geral de Proteção de Dados
- **Zero Configuração**: Funciona out-of-the-box para dados brasileiros
- **Validação Real**: CPF e CNPJ são validados com algoritmo oficial (não apenas regex)
- **Pseudonimização Consistente**: Mesmo input = mesmo output (útil para FKs)
- **Laravel Ready**: ServiceProvider, Facade, Middleware e Trait inclusos

---

## Instalação

```bash
composer require richardmsbr/privacy-shield-br
```

### Laravel

O ServiceProvider é registrado automaticamente via auto-discovery.

Para publicar a configuração:

```bash
php artisan vendor:publish --tag=privacy-shield-config
```

---

## Uso Rápido

### Mascarar Dados

```php
use PrivacyShield\Privacy;

// String simples
$texto = "Meu CPF é 123.456.789-09 e meu email é joao@email.com";
echo Privacy::mask($texto);
// Output: "Meu CPF é ***.456.789-** e meu email é j***@e****.com"

// Array
$usuario = [
    'nome' => 'João Silva',
    'cpf' => '123.456.789-09',
    'email' => 'joao.silva@empresa.com.br',
    'telefone' => '(11) 99999-8888',
];

print_r(Privacy::mask($usuario));
// Output:
// [
//     'nome' => 'João Silva',
//     'cpf' => '***.456.789-**',
//     'email' => 'j***.s****@e******.com.br',
//     'telefone' => '(11) *****-8888',
// ]
```

### Detectar Dados Sensíveis

```php
use PrivacyShield\Privacy;

$texto = "CPF: 123.456.789-09, Email: teste@email.com, Tel: 11999998888";

// Contagem simples
$resultado = Privacy::scan($texto);
// ['cpf' => 1, 'email' => 1, 'phone' => 1, 'total' => 3]

// Verificação rápida
if (Privacy::hasSensitiveData($texto)) {
    echo "ALERTA: Texto contém dados pessoais!";
}

// Detalhes completos
$detalhes = Privacy::scanDetailed($texto);
// [
//     ['type' => 'cpf', 'value' => '123.456.789-09', 'position' => 5],
//     ['type' => 'email', 'value' => 'teste@email.com', 'position' => 25],
//     ...
// ]
```

### Pseudonimização (Dados Falsos Consistentes)

```php
use PrivacyShield\Privacy;

$usuario = [
    'cpf' => '123.456.789-09',
    'email' => 'joao@email.com',
    'telefone' => '(11) 99999-8888',
];

// Pseudonimiza com seed (mesmo seed = mesmo resultado)
$fake = Privacy::pseudonymize($usuario, 'user_123');
// [
//     'cpf' => '987.654.321-00',  // CPF válido!
//     'email' => 'maria.santos42@gmail.com',
//     'telefone' => '(21) 98765-4321',
// ]

// Chamar novamente com mesmo seed = mesmo resultado
$fake2 = Privacy::pseudonymize($usuario, 'user_123');
// Idêntico a $fake - útil para manter consistência em FKs
```

### Remover Completamente (Redact)

```php
use PrivacyShield\Privacy;

$texto = "Cliente João, CPF 123.456.789-09, ligou às 14h";
echo Privacy::redact($texto);
// Output: "Cliente João, CPF [REMOVIDO], ligou às 14h"
```

---

## Integração Laravel

### Facade

```php
use PrivacyShield\Laravel\Facades\Privacy;

// Mesmos métodos disponíveis
Privacy::mask($dados);
Privacy::scan($texto);
Privacy::pseudonymize($dados);
```

### Middleware

```php
// routes/api.php

// Mascara automaticamente respostas JSON
Route::get('/users', [UserController::class, 'index'])
    ->middleware('privacy.mask');

// Sanitiza logs de requisição
Route::post('/checkout', [CheckoutController::class, 'store'])
    ->middleware('privacy.log');
```

### Trait Anonymizable em Models

```php
use PrivacyShield\Laravel\Traits\Anonymizable;

class User extends Model
{
    use Anonymizable;

    // Define campos sensíveis (opcional - tem padrões)
    protected array $anonymizable = ['cpf', 'email', 'phone', 'name'];
}
```

**Uso:**

```php
$user = User::find(1);

// Retorna cópia mascarada (não altera original)
$masked = $user->masked();
echo $masked->cpf; // ***.456.789-**

// Array mascarado
$array = $user->toMaskedArray();

// Pseudonimiza (dados falsos consistentes)
$fake = $user->pseudonymized();

// Direito ao Esquecimento (LGPD Art. 18)
// CUIDADO: Altera e salva no banco!
$user->forget();

// Verifica se tem dados sensíveis
if ($user->hasSensitiveData()) {
    // ...
}
```

---

## Validação de CPF/CNPJ

A biblioteca valida CPF e CNPJ usando o algoritmo oficial (dígitos verificadores), não apenas regex:

```php
use PrivacyShield\Detectors\Detector;

$detector = new Detector();

// CPFs válidos são detectados
$detector->isValidCpf('123.456.789-09'); // true
$detector->isValidCpf('111.111.111-11'); // false (sequência inválida)
$detector->isValidCpf('123.456.789-00'); // false (dígitos errados)

// Mesma validação para CNPJ
$detector->isValidCnpj('11.222.333/0001-81'); // true
```

---

## Geração de Dados Falsos Válidos

A pseudonimização gera dados que passam em validações:

```php
use PrivacyShield\Pseudonymizer;

$pseudo = new Pseudonymizer();

// Gera CPF válido
$cpf = $pseudo->generateFakeCpf('seed_123');
// 847.293.156-04 (válido!)

// Gera CNPJ válido
$cnpj = $pseudo->generateFakeCnpj('seed_123');
// 84.729.315/0001-60 (válido!)

// Gera nome brasileiro
$nome = $pseudo->generateFakeName('seed_123');
// "Fernanda Oliveira"

// Gera email realista
$email = $pseudo->generateFakeEmail('seed_123');
// "fernanda.oliveira42@gmail.com"

// Gera telefone com DDD válido
$tel = $pseudo->generateFakePhone('seed_123');
// "(11) 98472-9315"
```

---

## Configuração

```php
// config/privacy-shield.php

return [
    // Caractere de máscara
    'mask_char' => '*',

    // Texto para redação completa
    'redact_text' => '[REMOVIDO]',

    // Detectores ativos
    'detectors' => [
        'cpf' => true,
        'cnpj' => true,
        'email' => true,
        'phone' => true,
        'pix' => true,
        'credit_card' => true,
    ],

    // Mascarar domínio do email
    'mask_email_domain' => true,

    // Log de requisições sanitizadas
    'log_requests' => false,
];
```

---

## LGPD Compliance

Esta biblioteca ajuda a cumprir os seguintes artigos da LGPD:

| Artigo | Requisito | Como a biblioteca ajuda |
|--------|-----------|------------------------|
| Art. 5º | Definição de dado pessoal | Detecta automaticamente dados pessoais |
| Art. 6º | Princípio da necessidade | Permite mascarar dados desnecessários |
| Art. 12 | Anonimização | Métodos `mask()` e `redact()` |
| Art. 18 | Direito ao esquecimento | Método `forget()` no Trait |
| Art. 46 | Medidas de segurança | Previne vazamento em logs/APIs |

---

## Casos de Uso

### 1. Logs Seguros

```php
// Antes (ERRADO - vaza dados)
Log::info('Usuário criado', $request->all());

// Depois (CORRETO)
Log::info('Usuário criado', Privacy::mask($request->all()));
```

### 2. Ambiente de Desenvolvimento

```php
// Copia produção para dev com dados anonimizados
$users = User::all();

foreach ($users as $user) {
    $user->cpf = Privacy::pseudonymize($user->cpf, $user->id);
    $user->email = Privacy::pseudonymize($user->email, $user->id);
    $user->save();
}
```

### 3. Export de Dados

```php
// API que retorna dados mascarados
return response()->json(Privacy::mask($usuarios));
```

### 4. Atendimento ao Cliente

```php
// Atendente vê dados parciais
$cliente = Cliente::find($id)->masked();
echo "CPF: {$cliente->cpf}"; // ***.456.789-**
```

---

## Tipos de Dados Detectados

| Tipo | Exemplo | Mascarado |
|------|---------|-----------|
| CPF | 123.456.789-09 | \*\*\*.456.789-\*\* |
| CNPJ | 12.345.678/0001-90 | \*\*.345.678/\*\*\*\*-\*\* |
| Email | joao@email.com | j\*\*\*@e\*\*\*\*.com |
| Telefone | (11) 99999-8888 | (11) \*\*\*\*\*-8888 |
| Cartão | 4111 1111 1111 1111 | \*\*\*\* \*\*\*\* \*\*\*\* 1111 |
| PIX (chave) | abc12345-1234-... | abc1\*\*\*\*\*\*\*\*5678 |

---

## Requisitos

- PHP 8.1+
- Laravel 10+ (opcional, para integração)

---

## Contribuindo

Contribuições são bem-vindas! Por favor:

1. Fork o projeto
2. Crie sua branch (`git checkout -b feature/nova-feature`)
3. Commit suas mudanças (`git commit -m 'Adiciona nova feature'`)
4. Push para a branch (`git push origin feature/nova-feature`)
5. Abra um Pull Request

---

## Licença

MIT License - veja [LICENSE](LICENSE) para detalhes.

---

## Autor

**Richard** - [@richardmsbr](https://github.com/richardmsbr)

---

## Links

- [Documentação LGPD](https://www.gov.br/cidadania/pt-br/acesso-a-informacao/lgpd)
- [GDPR](https://gdpr.eu/)
- [Packagist](https://packagist.org/packages/richardmsbr/privacy-shield-br)

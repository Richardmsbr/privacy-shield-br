<?php

declare(strict_types=1);

namespace PrivacyShield\Laravel\Traits;

use PrivacyShield\Privacy;

/**
 * Trait para anonimização em Models Eloquent
 *
 * Adicione este trait ao seu Model para ter métodos de
 * anonimização automáticos.
 *
 * @example
 * class User extends Model
 * {
 *     use Anonymizable;
 *
 *     protected array $anonymizable = ['cpf', 'email', 'phone'];
 * }
 *
 * // Uso:
 * $user->anonymize(); // Retorna model com dados anonimizados
 * $user->toAnonymizedArray(); // Array com dados anonimizados
 * User::anonymizeAll(); // Anonimiza todos os registros no banco
 */
trait Anonymizable
{
    /**
     * Retorna instância com dados mascarados (não persiste)
     */
    public function masked(): static
    {
        $clone = clone $this;
        $attributes = $clone->getAttributes();

        foreach ($this->getAnonymizableAttributes() as $attribute) {
            if (isset($attributes[$attribute])) {
                $clone->$attribute = Privacy::mask($attributes[$attribute]);
            }
        }

        return $clone;
    }

    /**
     * Retorna array com dados mascarados
     */
    public function toMaskedArray(): array
    {
        return Privacy::mask($this->toArray());
    }

    /**
     * Retorna instância com dados pseudonimizados
     */
    public function pseudonymized(?string $seed = null): static
    {
        $clone = clone $this;
        $effectiveSeed = $seed ?? (string) $this->getKey();

        foreach ($this->getAnonymizableAttributes() as $attribute) {
            if (isset($clone->$attribute)) {
                $clone->$attribute = Privacy::pseudonymize(
                    $clone->$attribute,
                    $effectiveSeed . '.' . $attribute
                );
            }
        }

        return $clone;
    }

    /**
     * Anonimiza e persiste no banco de dados
     *
     * CUIDADO: Esta operação é irreversível!
     */
    public function anonymizeAndSave(): bool
    {
        foreach ($this->getAnonymizableAttributes() as $attribute) {
            if (isset($this->$attribute)) {
                $this->$attribute = Privacy::pseudonymize(
                    $this->$attribute,
                    (string) $this->getKey() . '.' . $attribute
                );
            }
        }

        return $this->save();
    }

    /**
     * Exercício do Direito ao Esquecimento (LGPD Art. 18)
     *
     * Anonimiza todos os dados pessoais do registro.
     * Use quando um usuário solicitar exclusão de dados.
     */
    public function forget(): bool
    {
        return $this->anonymizeAndSave();
    }

    /**
     * Verifica se o model contém dados sensíveis
     */
    public function hasSensitiveData(): bool
    {
        foreach ($this->getAnonymizableAttributes() as $attribute) {
            if (isset($this->$attribute) && Privacy::hasSensitiveData((string) $this->$attribute)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Escaneia e retorna relatório de dados sensíveis
     */
    public function scanSensitiveData(): array
    {
        $report = [];

        foreach ($this->getAnonymizableAttributes() as $attribute) {
            if (isset($this->$attribute)) {
                $scan = Privacy::scan((string) $this->$attribute);
                if ($scan['total'] > 0) {
                    $report[$attribute] = $scan;
                }
            }
        }

        return $report;
    }

    /**
     * Retorna lista de atributos anonimizáveis
     */
    protected function getAnonymizableAttributes(): array
    {
        // Propriedade definida no Model
        if (property_exists($this, 'anonymizable')) {
            return $this->anonymizable;
        }

        // Atributos padrão sensíveis
        return [
            'cpf', 'cnpj', 'email', 'phone', 'telefone', 'celular',
            'name', 'nome', 'full_name', 'nome_completo',
            'address', 'endereco', 'cep', 'rg',
        ];
    }

    /**
     * Scope para buscar registros com dados sensíveis
     */
    public function scopeWithSensitiveData($query)
    {
        return $query->get()->filter(fn($model) => $model->hasSensitiveData());
    }
}

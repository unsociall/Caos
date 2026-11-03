# CAOS Memory Integrity Guard — ciclo incremental

## Escopo
Implementação isolada e sem dependências externas para Android/Termux, PC e servidor.
Nenhuma migração ou modificação de registros existentes é realizada.

## API
- `seal(record)`: retorna cópia com `integrity_hash` SHA-256.
- `verify(record)`: retorna `False` para hash ausente, registro alterado ou versão incompatível.
- `digest(record)`: hash de JSON canônico sobre `id`, `content`, `schema_version`.

## Integração futura
1. Localizar a implementação real de persistência nas builds disponíveis.
2. Adicionar verificação na leitura e selo na gravação em um adaptador.
3. Não recalcular hash automaticamente em registros legados; usar migração explícita.
4. Definir política de quarentena, métricas e backup para registros corrompidos.

## Segurança
SHA-256 não autentica a origem. Atacantes que podem modificar o registro também podem
recalcular o hash. Para integridade autenticada, planejar HMAC ou assinaturas, com
gerenciamento seguro de chaves. Campos extras não são cobertos pelo hash.

## Testes
`python -m unittest discover -s tests -p 'test_caos_integrity.py' -v`

## Limitações
Este módulo é uma referência integrável, não está conectado ao banco de dados do CAOS.
Não há garantia de compatibilidade com o esquema de memória de builds anteriores.

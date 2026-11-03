# CAOS — autenticidade opcional da memória (HMAC-SHA256)

Implementação adicional, sem migração e sem dependências externas. Usa a serialização canônica de `caos_integrity._payload`, com separação de domínio e identificador de chave incluído no MAC.

## Uso

```python
import secrets
from caos_authenticated_integrity import authenticate, verify_authenticated

key = secrets.token_bytes(32)  # demonstrativo; em produção carregar de armazenamento protegido
record = {"id": "m1", "content": "exemplo", "schema_version": 1}
signed = authenticate(record, secret=key, key_id="local-v1")
assert verify_authenticated(signed, keys={"local-v1": key})
```

Nunca registrar, versionar ou enviar a chave ao GitHub. O exemplo gera chave efêmera: não usar como estratégia de persistência, pois registros antigos se tornam impossíveis de verificar após reinício. Configurar armazenamento seguro e backup das chaves antes da integração. Registros sem `auth_tag` são rejeitados pela verificação autenticada; não há migração implícita. `integrity_hash` legado pode coexistir, mas não é autenticado. Os demais campos extras também não são autenticados.

## Segurança e limitações

HMAC detecta adulterações por quem não possui a chave, mas não oferece confidencialidade, prevenção de replay, proteção contra exclusão ou garantia contra um processo comprometido com acesso à chave. O formato v1 autentica apenas id, content e schema_version; não use campos extras para decisões de segurança. Uma chave comprometida exige rotação supervisionada. Não reutilizar a chave em outros protocolos.

## Testes

`python -m unittest discover -s tests -p 'test_caos_authenticated_integrity.py' -v`

## Integração

Identificar primeiro o adaptador real de memória, criar política de chaves e de migração explícita, testar em cópia dos dados e manter rollback. Não há alterações no banco nem no mecanismo cognitivo neste ciclo.

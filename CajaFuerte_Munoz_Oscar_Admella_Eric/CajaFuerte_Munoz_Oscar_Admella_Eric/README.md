# CajaFuerte

Aplicación de consola en C# (.NET 10, versión LTS) que cifra y descifra ficheros `.txt` a partir de una contraseña, usando únicamente `System.Security.Cryptography`.

## Uso

```
dotnet build -c Release

CajaFuerte cifrar    <fichero_entrada.txt> <fichero_salida.caja> [contraseña]
CajaFuerte descifrar <fichero_salida.caja> <fichero_recuperado>  [contraseña]
```

Con `dotnet run`: `dotnet run -- cifrar secreto.txt secreto.caja`

Si se omite la contraseña, el programa la pide por teclado sin mostrarla (y al cifrar la pide dos veces). Es la forma recomendada: una contraseña escrita como argumento queda en el historial de la consola y es visible en la lista de procesos. Se admite como argumento para respetar la sintaxis del enunciado, pero el programa avisa.

Códigos de salida: `0` correcto · `1` error de uso · `2` error de fichero · `3` integridad fallida (contraseña incorrecta o fichero manipulado) · `4` plataforma sin AES-GCM.

## Estándares aplicados

| Requisito | Implementación | Dónde |
|---|---|---|
| AES-256 | Clave de 32 bytes | `CifradorCaja.TamanoClave` |
| Cifrado autenticado | `AesGcm`, tag de 16 bytes | `CifradorCaja.Cifrar/Descifrar` |
| Derivación de clave | `Rfc2898DeriveBytes.Pbkdf2`, HMAC-SHA256, 600.000 iteraciones | `CifradorCaja.DerivarClave` |
| Sal | 16 bytes de `RandomNumberGenerator`, nueva en cada fichero | `CifradorCaja.Cifrar` |
| Nonce | 12 bytes de `RandomNumberGenerator`, nuevo en cada cifrado | `CifradorCaja.Cifrar` |
| Integridad | `AesGcm.Decrypt` verifica el tag y lanza `AuthenticationTagMismatchException`; el programa avisa y no escribe nada | `CifradorCaja.Descifrar`, `Program.Main` |
| Prohibidos | Ni DES, 3DES, RC4, MD5, SHA-1 ni ECB. No se usa `System.Random` | — |

## Formato del fichero `.caja`

Documentado en detalle al principio de `Program.cs`.

| Offset | Tamaño | Bloque |
|---|---|---|
| 0x00 | 4 | Número mágico `CAJA` (43 41 4A 41) |
| 0x04 | 1 | Versión del formato (01) |
| 0x05 | 16 | Sal de PBKDF2 |
| 0x15 | 12 | Nonce de AES-GCM |
| 0x21 | 16 | Tag de autenticación GCM |
| 0x31 | N | Texto cifrado (hasta el final del fichero) |

La cabecera (número mágico + versión) se autentica como datos asociados (AAD) de GCM, de modo que modificar **cualquier** byte del fichero hace fallar la verificación.

## Decisiones de diseño

- **GCM en vez de CBC + HMAC**: GCM es cifrado autenticado en una sola primitiva; evita errores típicos de CBC+HMAC (orden incorrecto, comparar el HMAC sin tiempo constante, usar la misma clave para ambos, *padding oracle*).
- **Nonce de 96 bits**: tamaño recomendado por NIST SP 800-38D para GCM. Reutilizar un nonce con la misma clave en GCM rompe la confidencialidad y permite falsificar tags; por eso se genera siempre nuevo. Además, como la sal también es nueva, cada fichero usa una clave distinta.
- **Sal**: impide ataques con tablas precalculadas y que dos ficheros con la misma contraseña compartan clave. No es secreta, por eso se guarda en claro en el fichero.
- **600.000 iteraciones**: hacen que cada intento de contraseña cueste tiempo, frenando los ataques de fuerza bruta y diccionario (recomendación OWASP para PBKDF2-HMAC-SHA256).
- **Contraseña incorrecta y fichero manipulado dan el mismo error**: GCM no puede distinguirlos (en ambos casos el tag no cuadra) y además no conviene dar pistas a un atacante.
- **Nunca se escriben datos sin verificar**: `Decrypt` comprueba el tag antes de devolver el texto plano; el fichero de salida se escribe solo después, a través de un temporal que se renombra, y nunca se sobrescribe un fichero existente.
- **Limpieza de memoria**: clave derivada, contraseña (como `char[]`) y texto plano se borran con `CryptographicOperations.ZeroMemory` / `Array.Clear` tras usarse.
- **Contraseña mínima de 12 caracteres al cifrar**: PBKDF2 frena la fuerza bruta, pero no salva una contraseña trivial.
- **Límite de 256 MiB**: `AesGcm` trabaja en memoria de una vez; el límite evita agotar la RAM.

## Cómo comprobar la detección de manipulación

1. Cifra un `.txt` y abre el `.caja` con un editor hexadecimal.
2. Cambia cualquier byte (de la cabecera, la sal, el nonce, el tag o el texto cifrado).
3. Intenta descifrarlo: el programa muestra `ERROR DE INTEGRIDAD` y termina con código 3 sin crear el fichero de salida.

# AES TypeScript Library

Una implementación completa de los modos de operación AES en TypeScript. Esta biblioteca proporciona una amplia gama de modos de cifrado, desde los básicos hasta los más avanzados, incluyendo modos autenticados y especializados.

## Tabla de Contenidos

- [Características](#características)
- [Instalación](#instalación)
- [Modos de Operación](#modos-de-operación)
- [Uso Básico](#uso-básico)
- [Uso Avanzado](#uso-avanzado)
- [Ejemplos](#ejemplos)
- [API](#api)
- [Testing](#testing)
- [Licencia](#licencia)

## Características

- ✅ Implementación completa de AES (128/192/256 bits)
- ✅ Todos los modos de operación estándar (ECB, CBC, CFB, OFB, CTR)
- ✅ Modos autenticados (GCM, CCM, EAX, OCB, CWC)
- ✅ Modos especializados (XTS para almacenamiento en bloque, FPE-FF1 para cifrado de formato preservado)
- ✅ Modos resistentes al mal uso de nonce (GCM-SIV, PMAC-SIV)
- ✅ Funciones de envoltura de claves (KW, KWP, TKW)
- ✅ Implementación pura en TypeScript sin dependencias externas
- ✅ Documentación completa en español
- ✅ Ejemplos detallados y casos de prueba
- ✅ Compatibilidad con Node.js y navegadores modernos

## Instalación

Como esta es una biblioteca TypeScript pura, simplemente copia los archivos a tu proyecto:

```bash
# Copiar los archivos a tu proyecto
cp -r core/crypto/aes-ts/* your-project/crypto/
```

O puedes importar directamente los módulos que necesites:

```typescript
import { AES } from './aes-ts/aes';
import { ModeOfOperationECB } from './aes-ts/modes/ecb';
// ... otros imports según sea necesario
```

## Modos de Operación

### Modos Básicos

| Modo | Descripción | Autenticación | Uso Típico |
|------|-------------|---------------|------------|
| [ECB](modes/ecb.ts) | Electronic Codebook | No | Aprendizaje, no recomendado para uso real |
| [CBC](modes/cbc.ts) | Cipher Block Chaining | No | Cifrado general de datos |
| [CFB](modes/cfb.ts) | Cipher Feedback | No | Transmisión de datos |
| [OFB](modes/ofb.ts) | Output Feedback | No | Transmisión de datos |
| [CTR](modes/ctr.ts) | Counter | No | Cifrado de alta velocidad |

### Modos Autenticados (AEAD)

| Modo | Descripción | Características | Uso Típico |
|------|-------------|-----------------|------------|
| [GCM](modes/gcm.ts) | Galois/Counter Mode | Eficiente, estándar NIST | TLS, comunicaciones seguras |
| [CCM](modes/ccm.ts) | Counter with CBC-MAC | Tamaño de tag variable | IEEE 802.11i (WiFi) |
| [EAX](modes/eax.ts) | Encrypt-and-Authenticate | Resiliente, nonce reutilizable | Comunicaciones seguras |
| [OCB](modes/ocb.ts) | Offset Codebook | Eficiente, patentes | Aplicaciones no patentadas |
| [CWC](modes/cwc.ts) | Carter-Wegman+Counter | Seguro, paralelizable | Cifrado autenticado |

### Modos Resistentes al Mal Uso de Nonce

| Modo | Descripción | Características | Uso Típico |
|------|-------------|-----------------|------------|
| [GCM-SIV](modes/gcm-siv.ts) | GCM with Synthetic IV | Nonce-misuse resistant | Entornos con nonce reusado |
| [PMAC-SIV](modes/pmac-siv.ts) | PMAC with Synthetic IV | Paralelizable, nonce-misuse resistant | Sistemas paralelos |

### Modos Especializados

| Modo | Descripción | Características | Uso Típico |
|------|-------------|-----------------|------------|
| [XTS](modes/xts.ts) | XEX-based tweaked-codebook | Sector-based encryption | Discos duros, almacenamiento |
| [FPE-FF1](modes/fpe-ff1.ts) | Format Preserving Encryption | Mantiene formato | Números de tarjeta, identificadores |
| [KW/KWP](modes/kw.ts) | Key Wrap/Key Wrap with Padding | Envoltura de claves | Gestión de claves criptográficas |
| [TKW](modes/tkw.ts) | Tweakable Key Wrap | Envoltura con tweak | Envoltura de claves con metadatos |

### Modos Personalizados/Híbridos

| Modo | Descripción | Características | Uso Típico |
|------|-------------|-----------------|------------|
| [HybridCTR](modes/hybrid-ctr.ts) | Hybrid Counter Mode | Combina múltiples técnicas | Aplicaciones personalizadas |

## Uso Básico

### Cifrado Simple

```typescript
import { AES } from './aes-ts/aes';
import { ModeOfOperationCTR } from './aes-ts/modes/ctr';

// Crear una clave (128, 192 o 256 bits)
const key = new Uint8Array(32); // Clave de 256 bits
crypto.getRandomValues(key); // Llenar con valores aleatorios

// Crear datos para cifrar
const plaintext = new TextEncoder().encode("Mensaje secreto");

// Inicializar el cifrador
const aes = new AES(key);
const ctr = new ModeOfOperationCTR(key);

// Cifrar
const ciphertext = ctr.encrypt(plaintext);

// Descifrar
const decrypted = ctr.decrypt(ciphertext);
const message = new TextDecoder().decode(decrypted);
```

### Cifrado Autenticado

```typescript
import { ModeOfOperationGCM } from './aes-ts/modes/gcm';

const key = new Uint8Array(32);
crypto.getRandomValues(key);

const plaintext = new TextEncoder().encode("Mensaje secreto");
const nonce = new Uint8Array(12); // 96 bits para GCM
crypto.getRandomValues(nonce);

const gcm = new ModeOfOperationGCM(key);
const { ciphertext, tag } = gcm.encrypt(plaintext, nonce);

// Para descifrar
const decrypted = gcm.decrypt(ciphertext, tag, nonce);
if (decrypted !== null) {
  const message = new TextDecoder().decode(decrypted);
  console.log(message);
} else {
  console.log("Autenticación fallida");
}
```

## Uso Avanzado

### Cifrado de Disco con XTS

```typescript
import { ModeOfOperationXTS } from './aes-ts/modes/xts';

// XTS requiere una clave del doble del tamaño normal
const key = new Uint8Array(64); // 256 bits * 2
crypto.getRandomValues(key);

const xts = new ModeOfOperationXTS(key);

// El tweak normalmente representa la posición del sector
const tweak = new Uint8Array(16);
tweak.set([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // Sector 1

const plaintext = new TextEncoder().encode("Datos del sector de disco");
const ciphertext = xts.encrypt(plaintext, tweak);
```

### Cifrado de Formato Preservado

```typescript
import { ModeOfOperationFPE_FF1 } from './aes-ts/modes/fpe-ff1';

const key = new Uint8Array(32);
crypto.getRandomValues(key);

// Cifrar un número de tarjeta de crédito manteniendo su formato
const ccNumber = "1234567890123456";
const tweak = new TextEncoder().encode("contexto");

const ff1 = new ModeOfOperationFPE_FF1(key, 10); // Radix 10 para dígitos
const encryptedCC = ff1.encrypt(ccNumber, tweak);
console.log(encryptedCC); // Algo como "9876543210987654"

const decryptedCC = ff1.decrypt(encryptedCC, tweak);
console.log(decryptedCC); // "1234567890123456"
```

## Ejemplos

La biblioteca incluye varios archivos de ejemplo:

- [example.ts](example.ts) - Ejemplo básico de uso
- [comprehensive-examples.ts](comprehensive-examples.ts) - Ejemplos detallados de todos los modos
- [fpe-examples.ts](fpe-examples.ts) - Ejemplos de cifrado de formato preservado
- [test-high-level.ts](test-high-level.ts) - Pruebas de la API de alto nivel

Para ejecutar los ejemplos:

```bash
# Ejecutar ejemplo básico
npx ts-node example.ts

# Ejecutar ejemplos completos
npx ts-node comprehensive-examples.ts
```

## API

### Clase Principal AES

```typescript
class AES {
  constructor(key: Uint8Array);
  encrypt(block: Uint8Array): Uint8Array; // Bloque de 16 bytes
  decrypt(block: Uint8Array): Uint8Array; // Bloque de 16 bytes
}
```

### Interfaz de Modos de Operación

Todos los modos de operación siguen un patrón similar:

```typescript
class ModeOfOperationX {
  constructor(key: Uint8Array, ...params);
  encrypt(plaintext: Uint8Array, ...params): Uint8Array | { ciphertext: Uint8Array, tag: Uint8Array };
  decrypt(ciphertext: Uint8Array, ...params): Uint8Array | Uint8Array | null;
}
```

## Testing

La biblioteca incluye pruebas unitarias para todos los modos de operación:

```bash
# Ejecutar pruebas
cd modes/_test
npx ts-node t.ecb.ts
npx ts-node t.cbc.ts
# ... ejecutar otras pruebas según sea necesario
```

También puedes ejecutar pruebas específicas:

```bash
# Ejecutar prueba del modo híbrido
npx ts-node modes/_test/t.hybrid-ctr.ts
```

## Contribuciones

1. Haz un fork del repositorio
2. Crea una rama para tu característica (`git checkout -b feature/NuevaCaracteristica`)
3. Realiza tus cambios y haz commit (`git commit -am 'Agrega nueva característica'`)
4. Haz push a la rama (`git push origin feature/NuevaCaracteristica`)
5. Crea un nuevo Pull Request

## Licencia

Esta biblioteca está licenciada bajo la licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

---

Desarrollado con ❤️ para proporcionar una implementación completa y bien documentada de AES en TypeScript.
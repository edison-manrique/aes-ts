import { AES } from "../aes"
import { Counter, ModeOfOperationCTR } from "./ctr"

/**
 * Implementación del modo de operación AES-GCM (Galois/Counter Mode).
 *
 * GCM es un modo de operación AEAD (Authenticated Encryption with Associated Data) que
 * proporciona confidencialidad, integridad y autenticidad. Combina el modo CTR para
 * cifrado con una función de autenticación basada en aritmética de campos de Galois.
 *
 * Características principales:
 * - **AEAD**: Proporciona cifrado autenticado con datos asociados.
 * - **Eficiente**: Solo requiere una aplicación de AES por bloque de datos.
 * - **Paralelizable**: Tanto el cifrado como la autenticación pueden realizarse en paralelo.
 * - **Nonce de 96 bits**: Recomendado para uso con nonces de 96 bits (12 bytes).
 * - **Etiqueta de 128 bits**: Genera una etiqueta de autenticación de 128 bits.
 *
 * Funcionamiento:
 * 1. Se usa CTR para cifrar el texto plano.
 * 2. Se calcula GHASH (función hash basada en multiplicación de Galois) sobre los datos asociados y el texto cifrado.
 * 3. Se combina el resultado de GHASH con el cifrado del bloque J0 para formar la etiqueta.
 *
 * Consideraciones de seguridad:
 * - **Nonce único**: El nonce debe ser único para cada cifrado con la misma clave.
 * - **Nonce predecible**: Con nonces predecibles, GCM es vulnerable a ataques.
 * - **Longitud de clave**: Se recomienda usar claves de 256 bits para mayor seguridad.
 * - **Límites de uso**: No se debe usar la misma clave para más de 2^32 cifrados.
 *
 * GCM es ampliamente utilizado en protocolos como TLS, IPsec y IEEE 802.11ad.
 * Es un estándar NIST y una opción popular para cifrado autenticado.
 *
 * @example
 * ```typescript
 * const key = new Uint8Array(16); // Clave de 128 bits
 * const nonce = new Uint8Array(12); // Nonce de 96 bits (recomendado)
 * const gcm = new ModeOfOperationGCM(key, nonce);
 * const plaintext = new TextEncoder().encode("Mensaje secreto");
 * const aad = new TextEncoder().encode("Datos asociados");
 * 
 * const { ciphertext, tag } = gcm.encrypt(plaintext, aad);
 * const decrypted = gcm.decrypt(ciphertext, tag, aad);
 * ```
 *
 * @see [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
 * para la especificación oficial del modo GCM.
 */
export class ModeOfOperationGCM {
  public readonly description = "Galois/Counter Mode"
  public readonly name = "gcm"

  private readonly aes: AES
  private readonly key: Uint8Array
  private readonly iv: Uint8Array

  // Clave de autenticación H, precalculada en el constructor.
  private readonly H: Uint8Array
  // Bloque pre-contador J0, precalculado en el constructor.
  private readonly J0: Uint8Array

  /**
   * Inicializa el modo de operación GCM con una clave y un vector de inicialización.
   * @param key La clave de cifrado, debe ser de 16, 24 o 32 bytes (128, 192 o 256 bits).
   * @param iv El vector de inicialización (nonce). Se recomienda 12 bytes, pero se aceptan otras longitudes.
   */
  constructor(key: Uint8Array, iv: Uint8Array) {
    this.aes = new AES(key)
    this.key = key
    this.iv = iv

    // Precalcular la clave de hash H = CIPH_K(0^128)
    this.H = this.aes.encrypt(new Uint8Array(16))

    // Precalcular el bloque pre-contador J0
    if (this.iv.length === 12) {
      // Caso especial y recomendado para un nonce de 96 bits (12 bytes)
      this.J0 = new Uint8Array(16)
      this.J0.set(this.iv)
      this.J0[15] = 1
    } else {
      // Caso para nonces de otra longitud, se hashean con GHASH
      this.J0 = this.ghash(new Uint8Array(0), this.iv)
    }
  }

  /**
   * Cifra y autentica los datos.
   * @param plaintext El texto plano a cifrar.
   * @param associatedData Datos adicionales que serán autenticados pero no cifrados.
   * @returns Un objeto con el `ciphertext` y la etiqueta de autenticación `tag`.
   */
  encrypt(plaintext: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): { ciphertext: Uint8Array; tag: Uint8Array } {
    const counter = new Counter(this.J0)
    counter.increment() // El contador para cifrado empieza en J0 + 1

    const ctr = new ModeOfOperationCTR(this.key, counter)
    const ciphertext = ctr.encrypt(plaintext)

    const ghashResult = this.ghash(associatedData, ciphertext)
    const S = this.aes.encrypt(this.J0) // Cifrar J0

    const tag = new Uint8Array(16)
    for (let i = 0; i < 16; i++) {
      tag[i] = ghashResult[i] ^ S[i]
    }

    return { ciphertext, tag }
  }

  /**
   * Descifra y verifica la autenticidad de los datos.
   * @param ciphertext El texto cifrado.
   * @param tag La etiqueta de autenticación recibida.
   * @param associatedData Los mismos datos asociados usados en el cifrado.
   * @returns El texto plano si la autenticación es exitosa, o `null` si falla.
   */
  decrypt(ciphertext: Uint8Array, tag: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): Uint8Array | null {
    if (tag.length !== 16) {
      return null // Etiqueta de longitud inválida
    }

    const ghashResult = this.ghash(associatedData, ciphertext)
    const S = this.aes.encrypt(this.J0)

    const expectedTag = new Uint8Array(16)
    for (let i = 0; i < 16; i++) {
      expectedTag[i] = ghashResult[i] ^ S[i]
    }

    // Comparación en tiempo constante para evitar ataques de temporización
    let tagsMatch = 0
    for (let i = 0; i < 16; i++) {
      tagsMatch |= tag[i] ^ expectedTag[i]
    }

    if (tagsMatch !== 0) {
      return null // ¡Fallo de autenticación!
    }

    const counter = new Counter(this.J0)
    counter.increment() // El contador para descifrado también empieza en J0 + 1

    const ctr = new ModeOfOperationCTR(this.key, counter)
    const plaintext = ctr.decrypt(ciphertext)

    return plaintext
  }

  /**
   * Multiplicación en el cuerpo de Galois GF(2^128).
   * @private
   */
  private galoisMultiply(x: Uint8Array, y: Uint8Array): Uint8Array<ArrayBuffer> {
    const R = 0xe1 // Polinomio de reducción
    const z = new Uint8Array(16)
    let v = new Uint8Array(y)

    for (let i = 0; i < 128; i++) {
      // Si el bit actual de x es 1, z ^= v
      if ((x[Math.floor(i / 8)] >> (7 - (i % 8))) & 1) {
        for (let j = 0; j < 16; j++) {
          z[j] ^= v[j]
        }
      }

      // Desplaza v un bit a la derecha
      const lsbSet = (v[15] & 1) !== 0
      for (let j = 15; j > 0; j--) {
        v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7)
      }
      v[0] = v[0] >> 1

      // Si el LSB de v era 1, z ^= R
      if (lsbSet) {
        v[0] ^= R
      }
    }
    return z
  }

  /**
   * Calcula el hash GHASH para los datos asociados y el texto cifrado.
   * @private
   */
  private ghash(associatedData: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    let Y = new Uint8Array(16)

    // Fase 1: Procesar datos asociados (AAD)
    for (let i = 0; i < associatedData.length; i += 16) {
      const block = associatedData.subarray(i, i + 16)
      for (let j = 0; j < block.length; j++) {
        Y[j] ^= block[j]
      }
      Y = this.galoisMultiply(Y, this.H)
    }

    // Fase 2: Procesar texto cifrado
    for (let i = 0; i < ciphertext.length; i += 16) {
      const block = ciphertext.subarray(i, i + 16)
      for (let j = 0; j < block.length; j++) {
        Y[j] ^= block[j]
      }
      Y = this.galoisMultiply(Y, this.H)
    }

    // Fase 3: Bloque final con longitudes
    const lenA = associatedData.length * 8
    const lenC = ciphertext.length * 8
    const finalBlock = new Uint8Array(16)

    // Escribir longitud de AAD (64 bits)
    for (let i = 0; i < 8; i++) {
      finalBlock[7 - i] = (lenA >> (i * 8)) & 0xff
    }
    // Escribir longitud de Ciphertext (64 bits)
    for (let i = 0; i < 8; i++) {
      finalBlock[15 - i] = (lenC >> (i * 8)) & 0xff
    }

    for (let j = 0; j < 16; j++) {
      Y[j] ^= finalBlock[j]
    }

    return this.galoisMultiply(Y, this.H)
  }
}
import { AES } from "../aes"
import { Counter, ModeOfOperationCTR } from "./ctr"

/**
 * Implementación del modo de operación AES-GCM-SIV (Galois/Counter Mode with Synthetic Initialization Vector).
 *
 * GCM-SIV es una variante del modo GCM que ofrece resistencia al mal uso de nonces.
 * A diferencia del GCM tradicional, GCM-SIV puede ser seguro incluso si se reutiliza el nonce,
 * aunque esto reducirá la privacidad a solo una garantía por clave.
 *
 * Características principales:
 * - **Resistencia al mal uso de Nonce**: Seguridad incluso con nonces repetidos.
 * - **Autenticación**: Proporciona cifrado autenticado (AEAD).
 * - **Eficiencia**: Diseñado para ser eficiente en implementaciones de software.
 * - **Derivación de claves**: Las claves de cifrado y autenticación se derivan de la clave maestra.
 *
 * Proceso:
 * 1. Se deriva un IV sintético a partir del nonce y los datos a cifrar.
 * 2. Se deriva una clave de autenticación y una clave de cifrado.
 * 3. Se calcula un POLYVAL (similar a GHASH) sobre los datos.
 * 4. Se combina el POLYVAL con el IV sintético para formar el tag.
 * 5. Se usa el tag como nonce para el modo CTR para cifrar los datos.
 *
 * @example
 * ```typescript
 * const key = new Uint8Array(32); // Clave de 256 bits
 * const gcmSiv = new ModeOfOperationGCM_SIV(key);
 * const plaintext = new TextEncoder().encode("Mensaje secreto");
 * const nonce = new Uint8Array(12); // 96-bit nonce
 * const aad = new TextEncoder().encode("Datos asociados");
 * 
 * const { ciphertext, tag } = gcmSiv.encrypt(plaintext, nonce, aad);
 * const decrypted = gcmSiv.decrypt(ciphertext, tag, nonce, aad);
 * ```
 *
 * @see [RFC 8452](https://tools.ietf.org/html/rfc8452) para la especificación oficial.
 */
export class ModeOfOperationGCM_SIV {
  public readonly description = "Galois/Counter Mode SIV (Nonce-Misuse Resistant)"
  public readonly name = "gcm-siv"

  private readonly masterKey: Uint8Array

  /**
   * Inicializa el modo de operación GCM-SIV con una clave maestra.
   * @param key La clave maestra, que debe ser de 16 bytes (AES-128) o 32 bytes (AES-256).
   */
  constructor(key: Uint8Array) {
    if (key.length !== 16 && key.length !== 32) {
      throw new Error("Tamaño de clave inválido para GCM-SIV (debe ser 16 o 32 bytes)")
    }
    this.masterKey = key
  }

  /**
   * Deriva las claves de autenticación y cifrado a partir de la clave maestra y el nonce.
   * Según la especificación en RFC 8452, Sección 4.
   * @private
   */
  private deriveKeys(nonce: Uint8Array): { authKey: Uint8Array; encKey: Uint8Array } {
    const aes = new AES(this.masterKey)
    const keyLen = this.masterKey.length
    const block = new Uint8Array(16)
    block.set(nonce, 4)

    const keyMaterial = new Uint8Array(keyLen === 16 ? 32 : 48)
    const numBlocks = keyLen === 16 ? 4 : 6

    for (let i = 0; i < numBlocks; i++) {
      // Escribir el contador como little-endian de 32 bits
      block[0] = i & 0xff
      block[1] = (i >> 8) & 0xff
      block[2] = (i >> 16) & 0xff
      block[3] = (i >> 24) & 0xff

      const encryptedBlock = aes.encrypt(block)
      keyMaterial.set(encryptedBlock.subarray(0, 8), i * 8)
    }

    const authKey = keyMaterial.subarray(0, 16)
    const encKey = keyMaterial.subarray(16)

    return { authKey, encKey }
  }

  /**
   * Multiplicación en el cuerpo de Galois GF(2^128) para POLYVAL.
   * El polinomio irreducible es x^128 + x^127 + x^126 + x^121 + 1.
   * @private
   */
  private polyvalMultiply(x: Uint8Array, y: Uint8Array): Uint8Array<ArrayBuffer> {
    const z = new Uint8Array(16)
    let v = new Uint8Array(y)

    for (let i = 0; i < 128; i++) {
      const xByteIndex = Math.floor(i / 8)
      const xBitIndex = 7 - (i % 8)

      if ((x[xByteIndex] >> xBitIndex) & 1) {
        for (let j = 0; j < 16; j++) {
          z[j] ^= v[j]
        }
      }

      const lsbSet = (v[15] & 1) !== 0
      for (let j = 15; j > 0; j--) {
        v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7)
      }
      v[0] >>= 1

      if (lsbSet) {
        v[0] ^= 0b11100001 // Polinomio de reducción para POLYVAL (0xE1)
      }
    }
    return z
  }

  /**
   * Calcula el hash POLYVAL para los datos.
   * @private
   */
  private polyval(authKey: Uint8Array, associatedData: Uint8Array, plaintext: Uint8Array): Uint8Array {
    let s = new Uint8Array(16)
    const aadPadded = this.padToBlockSize(associatedData)
    const plaintextPadded = this.padToBlockSize(plaintext)

    const blocks = [aadPadded, plaintextPadded, this.createLengthBlock(associatedData.length, plaintext.length)]

    for (const data of blocks) {
      for (let i = 0; i < data.length; i += 16) {
        const block = data.subarray(i, i + 16)
        for (let j = 0; j < 16; j++) {
          s[j] ^= block[j]
        }
        s = this.polyvalMultiply(s, authKey)
      }
    }

    return s
  }

  private padToBlockSize(data: Uint8Array): Uint8Array {
    const len = data.length
    const remainder = len % 16
    if (remainder === 0) return data

    const padded = new Uint8Array(len + (16 - remainder))
    padded.set(data)
    return padded
  }

  private createLengthBlock(aadLen: number, plaintextLen: number): Uint8Array {
    const lenBlock = new Uint8Array(16)
    const view = new DataView(lenBlock.buffer)
    view.setBigUint64(0, BigInt(aadLen * 8), true) // little-endian
    view.setBigUint64(8, BigInt(plaintextLen * 8), true) // little-endian
    return lenBlock
  }

  /**
   * Cifra y autentica los datos usando AES-GCM-SIV.
   * @param plaintext El texto plano a cifrar.
   * @param nonce El nonce de 96 bits (12 bytes). No debe reutilizarse por seguridad.
   * @param associatedData Datos adicionales que serán autenticados pero no cifrados.
   * @returns Un objeto con el `ciphertext` y la etiqueta de autenticación `tag`.
   */
  encrypt(plaintext: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): { ciphertext: Uint8Array; tag: Uint8Array } {
    if (nonce.length !== 12) {
      throw new Error("Tamaño de nonce inválido para GCM-SIV (debe ser 12 bytes)")
    }

    // 1. Derivación de claves
    const { authKey, encKey } = this.deriveKeys(nonce)
    const aesEnc = new AES(encKey)

    // 2. Cálculo de la etiqueta (Tag)
    const polyvalResult = this.polyval(authKey, associatedData, plaintext)

    const tagMaterial = new Uint8Array(16)
    tagMaterial.set(nonce, 0)
    for (let i = 0; i < 12; i++) {
      tagMaterial[i] ^= polyvalResult[i]
    }
    tagMaterial[12] = polyvalResult[12]
    tagMaterial[13] = polyvalResult[13]
    tagMaterial[14] = polyvalResult[14]
    tagMaterial[15] = polyvalResult[15]

    tagMaterial[15] &= 0x7f // Poner a 0 el bit más significativo

    const tag = aesEnc.encrypt(tagMaterial)

    // 3. Cifrado del texto plano con CTR
    const initialCounter = new Uint8Array(tag)
    initialCounter[15] |= 0x80 // Poner a 1 el bit más significativo

    const counter = new Counter(initialCounter)
    const ctr = new ModeOfOperationCTR(encKey, counter)
    const ciphertext = ctr.encrypt(plaintext)

    return { ciphertext, tag }
  }

  /**
   * Descifra y verifica la autenticidad de los datos.
   * @param ciphertext El texto cifrado.
   * @param tag La etiqueta de autenticación recibida.
   * @param nonce El mismo nonce usado en el cifrado.
   * @param associatedData Los mismos datos asociados usados en el cifrado.
   * @returns El texto plano si la autenticación es exitosa, o `null` si falla.
   */
  decrypt(ciphertext: Uint8Array, tag: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): Uint8Array | null {
    if (nonce.length !== 12) {
      throw new Error("Tamaño de nonce inválido para GCM-SIV (debe ser 12 bytes)")
    }
    if (tag.length !== 16) {
      return null // Etiqueta inválida
    }

    // 1. Derivación de claves
    const { authKey, encKey } = this.deriveKeys(nonce)

    // 2. Descifrado del texto cifrado con CTR
    const initialCounter = new Uint8Array(tag)
    initialCounter[15] |= 0x80 // Poner a 1 el bit más significativo

    const counter = new Counter(initialCounter)
    const ctr = new ModeOfOperationCTR(encKey, counter)
    const plaintext = ctr.decrypt(ciphertext)

    // 3. Recalcular la etiqueta esperada y verificar
    const polyvalResult = this.polyval(authKey, associatedData, plaintext)

    const tagMaterial = new Uint8Array(16)
    tagMaterial.set(nonce, 0)
    for (let i = 0; i < 12; i++) {
      tagMaterial[i] ^= polyvalResult[i]
    }
    tagMaterial[12] = polyvalResult[12]
    tagMaterial[13] = polyvalResult[13]
    tagMaterial[14] = polyvalResult[14]
    tagMaterial[15] = polyvalResult[15]

    tagMaterial[15] &= 0x7f // Poner a 0 el bit más significativo

    const aesEnc = new AES(encKey)
    const expectedTag = aesEnc.encrypt(tagMaterial)

    // Comparación en tiempo constante para evitar ataques de temporización
    let tagsMatch = 0
    for (let i = 0; i < 16; i++) {
      tagsMatch |= tag[i] ^ expectedTag[i]
    }

    if (tagsMatch !== 0) {
      return null // ¡Fallo de autenticación!
    }

    return plaintext
  }
}

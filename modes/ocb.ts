import { AES } from "../aes"
import { xor } from "./utils/xor"


/**
 * Implementación del modo de operación AES-OCB (Offset Codebook Mode, versión 3).
 *
 * OCB es un modo de operación de cifrado autenticado que combina cifrado y autenticación
 * en un solo paso, siendo más eficiente que los enfoques que realizan estas operaciones por separado.
 *
 * Características principales:
 * - **Eficiencia**: Combina cifrado y autenticación en una sola pasada.
 * - **Autenticación**: Proporciona autenticación tanto del texto cifrado como de datos adicionales.
 * - **Paralelismo**: Permite operaciones paralelas de cifrado y autenticación.
 * - **Flexibilidad**: Soporta longitudes de tag variables.
 *
 * Proceso:
 * 1. Se procesa el texto plano en bloques, usando offsets derivados de un nonce.
 * 2. Los bloques se cifran usando una combinación de offsets y la clave.
 * 3. Se genera un tag de autenticación basado en los bloques cifrados y datos adicionales.
 *
 * @example
 * ```typescript
 * const key = new Uint8Array(32); // Clave de 256 bits
 * const ocb = new ModeOfOperationOCB(key, 16); // Tag de 16 bytes
 * const plaintext = new TextEncoder().encode("Mensaje secreto");
 * const nonce = new Uint8Array(12); // Nonce de 96 bits
 * const aad = new TextEncoder().encode("Datos asociados");
 * 
 * const { ciphertext, tag } = ocb.encrypt(plaintext, nonce, aad);
 * const decrypted = ocb.decrypt(ciphertext, tag, nonce, aad);
 * ```
 *
 * @see [RFC 7253](https://tools.ietf.org/html/rfc7253) para la especificación oficial de OCB3.
 */
export class ModeOfOperationOCB {
  public readonly description = "Offset Codebook Mode (OCB3)"
  public readonly name = "ocb"

  private readonly aes: AES
  private readonly tagSize: number

  private readonly L_star: Uint8Array
  private readonly L_dollar: Uint8Array
  private readonly L_series: Uint8Array[]

  /**
   * Inicializa el modo de operación OCB con una clave maestra.
   * @param key La clave maestra AES.
   * @param tagSize El tamaño del tag de autenticación (entre 8 y 16 bytes).
   */
  constructor(key: Uint8Array, tagSize: number = 16) {
    if (tagSize < 8 || tagSize > 16) {
      throw new Error("Tamaño de etiqueta OCB inválido (debe estar entre 8 y 16)")
    }
    this.aes = new AES(key)
    this.tagSize = tagSize

    this.L_star = this.aes.encrypt(new Uint8Array(16))
    this.L_dollar = this._double(this.L_star)

    this.L_series = [this.L_star] // L_series[0] es L_0 = L_*
    for (let i = 0; i < 64; i++) {
      this.L_series.push(this._double(this.L_series[i]))
    }
  }

  private _shiftLeft(bytes: Uint8Array, bits: number): Uint8Array {
    const byteShift = Math.floor(bits / 8)
    const bitShift = bits % 8
    const result = new Uint8Array(bytes.length)

    if (bitShift === 0) {
      for (let i = 0; i < bytes.length - byteShift; i++) {
        result[i] = bytes[i + byteShift]
      }
    } else {
      const invBitShift = 8 - bitShift
      for (let i = 0; i < bytes.length; i++) {
        const high = i + byteShift < bytes.length ? bytes[i + byteShift] << bitShift : 0
        const low = i + byteShift + 1 < bytes.length ? bytes[i + byteShift + 1] >>> invBitShift : 0
        result[i] = (high | low) & 0xff
      }
    }
    return result
  }

  private _double(block: Uint8Array): Uint8Array<ArrayBuffer> {
    const doubled = new Uint8Array(16)
    const msbSet = (block[0] & 0x80) !== 0
    for (let i = 0; i < 15; i++) {
      doubled[i] = ((block[i] << 1) | (block[i + 1] >> 7)) & 0xff
    }
    doubled[15] = (block[15] << 1) & 0xff
    if (msbSet) {
      doubled[15] ^= 0x87
    }
    return doubled
  }

  private _ntz(n: number): number {
    if (n === 0) return 128
    let count = 0
    while ((n & 1) === 0) {
      n >>= 1
      count++
    }
    return count
  }

  private _ocb_process(data: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array, isEncryption: boolean): { output: Uint8Array; tag: Uint8Array } {
    if (nonce.length === 0 || nonce.length > 15) {
      throw new Error("Longitud de Nonce inválida para OCB (debe ser de 1 a 15 bytes)")
    }

    // --- Preparación ---
    const tmp = new Uint8Array(16)
    tmp[0] = (this.tagSize * 8) << 1 // Corregido según RFC, bits 1-6 para el taglen
    tmp.set(nonce, 16 - nonce.length)
    tmp[15 - nonce.length] |= 1

    const ktop = this.aes.encrypt(tmp)
    const stretch = new Uint8Array(24)
    stretch.set(ktop)
    stretch.set(xor(ktop.subarray(0, 8), ktop.subarray(1, 9)), 16)

    const bottom = tmp[15] & 0x3f
    const initialOffset = this._shiftLeft(stretch, bottom).subarray(0, 16)

    // --- Procesamiento de Datos Asociados (AAD) ---
    let authChecksum = new Uint8Array(16)
    let authOffset = new Uint8Array(16)
    for (let i = 0; i < associatedData.length; i += 16) {
      authOffset = this._double(authOffset === this.L_star ? this._double(this.L_star) : authOffset) // RFC HASH
      const block = associatedData.subarray(i, i + 16)
      const processedBlock = this.aes.encrypt(xor(block.length === 16 ? block : this._pad(block), authOffset))
      authChecksum = xor(authChecksum, processedBlock)
    }

    // --- Procesamiento Principal ---
    const output = new Uint8Array(data.length)
    let mainChecksum = new Uint8Array(16)
    let mainOffset = new Uint8Array(initialOffset)
    const numBlocks = Math.ceil(data.length / 16)

    for (let i = 1; i <= numBlocks; i++) {
      mainOffset = xor(mainOffset, this.L_series[this._ntz(i)])
      const from = (i - 1) * 16
      const to = from + 16
      const block = data.subarray(from, Math.min(to, data.length))

      // --- LÓGICA CRÍTICA CORREGIDA ---
      if (block.length < 16) {
        // Último bloque (parcial)
        const offsetStar = xor(mainOffset, this.L_star)
        const pad = this.aes.encrypt(offsetStar)
        const plaintextPartial = xor(block, pad.subarray(0, block.length))

        output.set(isEncryption ? plaintextPartial : block, from)
        if (!isEncryption) output.set(plaintextPartial, from) // En descifrado, la salida es el texto plano

        mainChecksum = xor(mainChecksum, this._pad(isEncryption ? block : plaintextPartial))
        break
      }

      if (isEncryption) {
        const encrypted = this.aes.encrypt(xor(block, mainOffset))
        output.set(xor(encrypted, mainOffset), from)
        mainChecksum = xor(mainChecksum, block)
      } else {
        const decryptedIntermediate = this.aes.decrypt(xor(block, mainOffset))
        const plaintextBlock = xor(decryptedIntermediate, mainOffset)
        output.set(plaintextBlock, from)
        mainChecksum = xor(mainChecksum, plaintextBlock) // Usar el texto plano recuperado
      }
    }

    // --- Cálculo de la Etiqueta Final ---
    const finalOffset = xor(mainOffset, this.L_dollar)
    const finalChecksum = this.aes.encrypt(xor(mainChecksum, finalOffset))
    const tag = xor(finalChecksum, authChecksum)

    return { output, tag: tag.subarray(0, this.tagSize) }
  }

  private _pad(block: Uint8Array): Uint8Array {
    const padded = new Uint8Array(16)
    padded.set(block)
    padded[block.length] = 0x80
    return padded
  }

  encrypt(plaintext: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): { ciphertext: Uint8Array; tag: Uint8Array } {
    const { output, tag } = this._ocb_process(plaintext, nonce, associatedData, true)
    return { ciphertext: output, tag }
  }

  decrypt(ciphertext: Uint8Array, tag: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): Uint8Array | null {
    if (tag.length !== this.tagSize) return null
    const { output, tag: calculatedTag } = this._ocb_process(ciphertext, nonce, associatedData, false)

    let tagsMatch = 0
    for (let i = 0; i < this.tagSize; i++) {
      tagsMatch |= tag[i] ^ calculatedTag[i]
    }

    if (tagsMatch !== 0) return null
    return output
  }
}

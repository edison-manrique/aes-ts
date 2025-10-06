import { AES } from "../aes"
import { xor } from "./utils/xor"
import { ModeOfOperationCTR } from "./ctr"

/**
 * Implementación del modo de operación AES-PMAC-SIV (Parallelizable MAC with Synthetic IV).
 *
 * PMAC-SIV es un modo de operación de cifrado autenticado que utiliza un enfoque de
 * IV sintético similar a SIV, pero basado en PMAC (Parallelizable MAC) en lugar de
 * un cifrado de bloque para la autenticación.
 *
 * Características principales:
 * - **Resistencia al mal uso de Nonce**: Seguridad incluso con nonces repetidos.
 * - **Autenticación paralelizable**: Utiliza PMAC que permite operaciones paralelas.
 * - **Eficiencia**: Diseñado para ser eficiente en entornos con múltiples núcleos.
 * - **IV sintético**: Deriva el IV/etiqueta de los datos a cifrar y autenticar.
 *
 * Proceso:
 * 1. Se calcula PMAC sobre el nonce, datos asociados y texto plano.
 * 2. Se combinan los resultados de PMAC para formar el IV sintético.
 * 3. Se utiliza el IV sintético como nonce para el modo CTR para cifrar los datos.
 * 4. Para descifrar, se verifica que el IV sintético coincida con el esperado.
 *
 * @example
 * ```typescript
 * const key = new Uint8Array(32); // Clave de 256 bits
 * const pmacSiv = new ModeOfOperationPMAC_SIV(key);
 * const plaintext = new TextEncoder().encode("Mensaje secreto");
 * const nonce = new Uint8Array(12); // Nonce de 96 bits
 * const aad = new TextEncoder().encode("Datos asociados");
 * 
 * const { ciphertext, iv_tag } = pmacSiv.encrypt(plaintext, nonce, aad);
 * const decrypted = pmacSiv.decrypt(ciphertext, iv_tag, nonce, aad);
 * ```
 */
export class ModeOfOperationPMAC_SIV {
  public readonly description = "PMAC-SIV (Nonce-Misuse Resistant)"
  public readonly name = "pmac-siv"

  private readonly aes: AES
  private readonly tagSize: number
  private readonly key: Uint8Array

  // --- Valores precalculados para PMAC (idénticos a los de OCB) ---
  private readonly L_star: Uint8Array
  // private readonly L_dollar: Uint8Array
  private readonly L_series: Uint8Array[]

  /**
   * Inicializa el modo de operación PMAC-SIV con una clave.
   * @param key La clave de cifrado, debe ser de 16, 24 o 32 bytes (128, 192 o 256 bits).
   * @param tagSize El tamaño del tag de autenticación (entre 8 y 16 bytes). Por defecto es 16 bytes.
   */
  constructor(key: Uint8Array, tagSize: number = 16) {
    if (tagSize < 8 || tagSize > 16) {
      throw new Error("Tamaño de etiqueta/IV inválido (debe estar entre 8 y 16)")
    }
    this.aes = new AES(key)
    this.tagSize = tagSize
    this.key = key

    // Precalcular valores L para la máxima eficiencia de PMAC
    this.L_star = this.aes.encrypt(new Uint8Array(16))
    // this.L_dollar = this._double(this.L_star)

    this.L_series = [this.L_star] // L_series[0] es L_0 = L_*
    for (let i = 0; i < 64; i++) {
      this.L_series.push(this._double(this.L_series[i]))
    }
  }

  private _double(block: Uint8Array): Uint8Array<ArrayBuffer> {
    const doubled = new Uint8Array(16)
    const msbSet = (block[0] & 0x80) !== 0
    for (let i = 0; i < 15; i++) {
      doubled[i] = ((block[i] << 1) | (block[i + 1] >>> 7)) & 0xff
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

  private _pad(block: Uint8Array): Uint8Array {
    const padded = new Uint8Array(16)
    padded.set(block)
    if (block.length < 16) {
      padded[block.length] = 0x80
    }
    return padded
  }

  /**
   * Calcula el PMAC sobre un conjunto de datos.
   * Esta es la función de autenticación del modo OCB.
   * @private
   */
  private _pmac(data: Uint8Array): Uint8Array {
    let checksum = new Uint8Array(16)
    let offset = new Uint8Array(16)

    const numBlocks = Math.ceil(data.length / 16)
    if (numBlocks === 0) {
      // Manejar datos vacíos
      offset = this._double(offset)
      checksum = xor(checksum, this._pad(data))
    } else {
      for (let i = 1; i <= numBlocks; i++) {
        offset = xor(offset, this.L_series[this._ntz(i)])
        const from = (i - 1) * 16
        const block = data.subarray(from, Math.min(from + 16, data.length))
        checksum = xor(checksum, block.length === 16 ? block : this._pad(block))
      }
    }

    const finalChecksum = xor(checksum, offset)
    return this.aes.encrypt(finalChecksum)
  }

  /**
   * Cifra y autentica los datos usando PMAC-SIV.
   * @param plaintext El texto plano a cifrar.
   * @param nonce El Nonce. ¡No debe reutilizarse!
   * @param associatedData Datos adicionales que serán autenticados pero no cifrados.
   * @returns Un objeto con el `ciphertext` y el `iv_tag` (IV Sintético/Etiqueta).
   */
  encrypt(plaintext: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): { ciphertext: Uint8Array; iv_tag: Uint8Array } {
    // 1. Calcular los PMACs de todos los componentes.
    const mac_nonce = this._pmac(nonce)
    const mac_aad = this._pmac(associatedData)
    const mac_plaintext = this._pmac(plaintext)

    // 2. Combinar los MACs para crear el IV Sintético / Etiqueta final.
    const iv_tag = xor(xor(mac_nonce, mac_aad), mac_plaintext)

    // 3. Cifrar el texto plano usando CTR, inicializado con el IV sintético.
    const ctr = new ModeOfOperationCTR(this.key, iv_tag)
    const ciphertext = ctr.encrypt(plaintext)

    return { ciphertext, iv_tag: iv_tag.subarray(0, this.tagSize) }
  }

  /**
   * Descifra y verifica la autenticidad de los datos.
   * @param ciphertext El texto cifrado.
   * @param iv_tag El IV Sintético / Etiqueta de autenticación recibida.
   * @param nonce El mismo Nonce usado en el cifrado.
   * @param associatedData Los mismos datos asociados usados en el cifrado.
   * @returns El texto plano si la autenticación es exitosa, o `null` si falla.
   */
  decrypt(ciphertext: Uint8Array, iv_tag: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): Uint8Array | null {
    if (iv_tag.length !== this.tagSize) {
      return null
    }

    // 1. Descifrar el texto cifrado usando CTR, inicializado con el IV/Tag recibido.
    // Creamos un IV de 16 bytes completo para pasarlo al constructor de CTR.
    const full_iv_tag = new Uint8Array(16)
    full_iv_tag.set(iv_tag)

    const ctr = new ModeOfOperationCTR(this.key, full_iv_tag)
    const plaintext = ctr.decrypt(ciphertext)

    // 2. Recalcular el IV/Tag esperado usando el texto plano descifrado.
    const mac_nonce = this._pmac(nonce)
    const mac_aad = this._pmac(associatedData)
    const mac_plaintext = this._pmac(plaintext) // ¡Importante! Usar el texto plano recién descifrado.

    const expected_iv_tag = xor(xor(mac_nonce, mac_aad), mac_plaintext)

    // 3. Comparar el IV/Tag recibido con el esperado en tiempo constante.
    let tagsMatch = 0
    for (let i = 0; i < this.tagSize; i++) {
      tagsMatch |= iv_tag[i] ^ expected_iv_tag[i]
    }

    if (tagsMatch !== 0) {
      return null // ¡Fallo de autenticación!
    }

    return plaintext
  }
}
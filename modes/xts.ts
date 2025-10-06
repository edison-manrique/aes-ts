import { AES } from "../aes"
import { xor } from "./utils/xor"

/**
 * Implementación del modo de operación AES-XTS (XEX-based tweaked-codebook mode with ciphertext stealing).
 *
 * XTS es un modo de operación diseñado específicamente para el cifrado de dispositivos de almacenamiento
 * en bloque como discos duros o memorias flash. Fue estandarizado por IEEE como parte del estándar 1619.
 *
 * Características principales:
 * - **Diseñado para almacenamiento**: Especialmente adecuado para cifrar datos en dispositivos de almacenamiento.
 * - **No proporciona autenticación**: Solo ofrece confidencialidad, no autenticación ni integridad.
 * - **Uso de tweaks**: Cada bloque se cifra con un tweak único que normalmente representa la posición del bloque.
 * - **Robusto contra patrones**: Evita patrones en el texto cifrado que podrían revelar información sobre el texto plano.
 *
 * Proceso:
 * 1. Se usa una clave para el cifrado y otra para generar valores tweak.
 * 2. Cada bloque se cifra usando el tweak correspondiente a su posición.
 * 3. Se utiliza "ciphertext stealing" para manejar datos que no son múltiplos del tamaño de bloque.
 *
 * @example
 * ```typescript
 * const key = new Uint8Array(64); // Clave de 512 bits (256 bits por cada subclave)
 * const xts = new ModeOfOperationXTS(key);
 * const plaintext = new TextEncoder().encode("Datos a cifrar en disco");
 * const tweak = new Uint8Array(16); // Representa la posición del bloque
 * 
 * const ciphertext = xts.encrypt(plaintext, tweak);
 * const decrypted = xts.decrypt(ciphertext, tweak);
 * ```
 *
 * @see [IEEE Std 1619-2018](https://ieeexplore.ieee.org/document/8269403) para el estándar oficial.
 * @see [NIST SP 800-38E](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38e.pdf) para recomendaciones.
 */
export class ModeOfOperationXTS {
  public readonly description = "XTS (for Block Storage)"
  public readonly name = "xts"

  private readonly aes1: AES
  private readonly aes2: AES

  /**
   * Inicializa el modo de operación XTS con una clave maestra.
   * @param key La clave maestra, que debe ser de 32 bytes (2x128 bits) o 64 bytes (2x256 bits).
   */
  constructor(key: Uint8Array) {
    if (key.length !== 32 && key.length !== 64) {
      throw new Error("Tamaño de clave inválido para XTS (debe ser 32 o 64 bytes)")
    }
    const keyLen = key.length / 2
    this.aes1 = new AES(key.subarray(0, keyLen))
    this.aes2 = new AES(key.subarray(keyLen))
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

  encrypt(plaintext: Uint8Array, tweak: Uint8Array): Uint8Array {
    if (plaintext.length < 16) throw new Error("Los datos para XTS deben ser >= 16 bytes.")
    if (tweak.length !== 16) throw new Error("El tweak para XTS debe ser de 16 bytes.")

    const ciphertext = new Uint8Array(plaintext.length)
    let currentTweak = this.aes2.encrypt(tweak)

    const numBlocks = Math.floor(plaintext.length / 16)
    const finalBlockSize = plaintext.length % 16

    // Procesar todos los bloques completos excepto los implicados en el CTS
    const iterationLimit = finalBlockSize === 0 ? numBlocks - 2 : numBlocks - 1
    for (let i = 0; i < iterationLimit; i++) {
      const from = i * 16
      const block = plaintext.subarray(from, from + 16)
      const encryptedBlock = this.aes1.encrypt(xor(block, currentTweak))
      ciphertext.set(xor(encryptedBlock, currentTweak), from)
      currentTweak = this._double(currentTweak)
    }

    if (finalBlockSize === 0) {
      // Caso 1: Los datos son un múltiplo del tamaño del bloque.
      // Se intercambian los dos últimos bloques después del cifrado.
      const penultimateBlockP = plaintext.subarray((numBlocks - 2) * 16, (numBlocks - 1) * 16)
      const lastBlockP = plaintext.subarray((numBlocks - 1) * 16)

      const tweak_m_minus_1 = new Uint8Array(currentTweak)
      const tweak_m = this._double(tweak_m_minus_1)

      const preCiphertext = this.aes1.encrypt(xor(penultimateBlockP, tweak_m_minus_1))
      const finalCiphertext = xor(this.aes1.encrypt(xor(lastBlockP, tweak_m)), tweak_m_minus_1)

      ciphertext.set(finalCiphertext, (numBlocks - 2) * 16)
      ciphertext.set(xor(preCiphertext, tweak_m), (numBlocks - 1) * 16)
    } else {
      // Caso 2: Hay un bloque parcial al final.
      const penultimateBlockP = plaintext.subarray((numBlocks - 1) * 16, numBlocks * 16)
      const finalPartialBlockP = plaintext.subarray(numBlocks * 16)

      const tweak_m_minus_1 = new Uint8Array(currentTweak)
      const tweak_m = this._double(tweak_m_minus_1)

      // Cifrar el penúltimo bloque para obtener los datos a robar
      const preCiphertext = this.aes1.encrypt(xor(penultimateBlockP, tweak_m_minus_1))
      const stolenData = preCiphertext.subarray(finalBlockSize)

      // El bloque final del texto cifrado es el inicio del pre-texto cifrado
      const finalCiphertextBlockC = preCiphertext.subarray(0, finalBlockSize)
      ciphertext.set(finalCiphertextBlockC, numBlocks * 16)

      // Construir el bloque para el penúltimo texto cifrado usando el texto plano robado
      const blockForPenultimateC = new Uint8Array(16)
      blockForPenultimateC.set(finalPartialBlockP)
      blockForPenultimateC.set(stolenData, finalPartialBlockP.length)

      const penultimateCiphertextBlockC = xor(this.aes1.encrypt(xor(blockForPenultimateC, tweak_m)), tweak_m_minus_1)
      ciphertext.set(penultimateCiphertextBlockC, (numBlocks - 1) * 16)
    }

    return ciphertext
  }

  decrypt(ciphertext: Uint8Array, tweak: Uint8Array): Uint8Array {
    if (ciphertext.length < 16) throw new Error("Los datos para XTS deben ser >= 16 bytes.")
    if (tweak.length !== 16) throw new Error("El tweak para XTS debe ser de 16 bytes.")

    const plaintext = new Uint8Array(ciphertext.length)
    let currentTweak = this.aes2.encrypt(tweak)

    const numBlocks = Math.floor(ciphertext.length / 16)
    const finalBlockSize = ciphertext.length % 16

    const iterationLimit = finalBlockSize === 0 ? numBlocks - 2 : numBlocks - 1
    for (let i = 0; i < iterationLimit; i++) {
      const from = i * 16
      const block = ciphertext.subarray(from, from + 16)
      const decryptedBlock = this.aes1.decrypt(xor(block, currentTweak))
      plaintext.set(xor(decryptedBlock, currentTweak), from)
      currentTweak = this._double(currentTweak)
    }

    if (finalBlockSize === 0) {
      // Caso 1: Los datos son un múltiplo del tamaño del bloque.
      const penultimateBlockC = ciphertext.subarray((numBlocks - 2) * 16, (numBlocks - 1) * 16)
      const lastBlockC = ciphertext.subarray((numBlocks - 1) * 16)

      const tweak_m_minus_1 = new Uint8Array(currentTweak)
      const tweak_m = this._double(tweak_m_minus_1)

      const prePlaintext = this.aes1.decrypt(xor(lastBlockC, tweak_m))
      const finalPlaintext = xor(this.aes1.decrypt(xor(penultimateBlockC, tweak_m_minus_1)), tweak_m)

      plaintext.set(xor(prePlaintext, tweak_m_minus_1), (numBlocks - 2) * 16)
      plaintext.set(finalPlaintext, (numBlocks - 1) * 16)
    } else {
      // Caso 2: Hay un bloque parcial al final.
      const penultimateBlockC = ciphertext.subarray((numBlocks - 1) * 16, numBlocks * 16)
      const finalPartialBlockC = ciphertext.subarray(numBlocks * 16)

      const tweak_m_minus_1 = new Uint8Array(currentTweak)
      const tweak_m = this._double(tweak_m_minus_1)

      // Descifrar el penúltimo bloque para obtener el "pre-texto plano"
      const prePlaintext = xor(this.aes1.decrypt(xor(penultimateBlockC, tweak_m_minus_1)), tweak_m)

      // El texto plano final es el inicio del pre-texto plano
      const finalPlaintextBlockP = prePlaintext.subarray(0, finalBlockSize)
      plaintext.set(finalPlaintextBlockP, numBlocks * 16)

      // Reconstruir el pre-texto cifrado usando el texto plano robado
      const preCiphertext = new Uint8Array(16)
      preCiphertext.set(finalPartialBlockC)
      preCiphertext.set(prePlaintext.subarray(finalBlockSize), finalPartialBlockC.length)

      const penultimatePlaintextBlockP = xor(this.aes1.decrypt(preCiphertext), tweak_m_minus_1)
      plaintext.set(penultimatePlaintextBlockP, (numBlocks - 1) * 16)
    }

    return plaintext
  }
}

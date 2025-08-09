import { AES } from "../aes"
import { xor } from "./utils/xor"

// --- AES-CBC-MAC (Cipher Block Chaining Message Authentication Code) ---
export class ModeOfOperationCBC_MAC {
  public readonly description = "CBC Message Authentication Code"
  public readonly name = "cbc-mac"

  private readonly aes: AES

  constructor(key: Uint8Array) {
    this.aes = new AES(key)
  }

  /**
   * Aplica el relleno CMAC/ISO-7816-4 al mensaje.
   * @private
   */
  private _pad(message: Uint8Array): Uint8Array {
    const remainder = message.length % 16
    const paddedSize = message.length - remainder + 16
    const padded = new Uint8Array(paddedSize)
    padded.set(message)
    padded[message.length] = 0x80
    // El resto de los bytes son 0 por defecto.
    return padded
  }

  /**
   * Genera una etiqueta de autenticación para un mensaje.
   * ADVERTENCIA: Solo es seguro para mensajes de longitud fija. Para longitud variable, use CMAC.
   * @param message El mensaje de texto plano a autenticar.
   * @param tagSize La longitud deseada para la etiqueta (se truncará si es menor de 16).
   * @returns La etiqueta de autenticación (MAC).
   */
  generateTag(message: Uint8Array, tagSize: number = 16): Uint8Array {
    if (tagSize > 16) {
      throw new Error("El tamaño de la etiqueta no puede ser mayor de 16 bytes.")
    }

    // CBC-MAC requiere relleno si el mensaje no es un múltiplo de 16.
    const dataToProcess = message.length % 16 === 0 && message.length > 0 ? message : this._pad(message)

    let lastCipherBlock = new Uint8Array(16) // IV siempre es cero

    for (let i = 0; i < dataToProcess.length; i += 16) {
      const block = dataToProcess.subarray(i, i + 16)
      const xoredBlock = xor(lastCipherBlock, block)
      lastCipherBlock = this.aes.encrypt(xoredBlock)
    }

    // La etiqueta es el último bloque cifrado, truncado al tamaño deseado.
    return lastCipherBlock.subarray(0, tagSize)
  }

  /**
   * Verifica la validez de una etiqueta de autenticación para un mensaje.
   * @param message El mensaje de texto plano original.
   * @param tag La etiqueta de autenticación a verificar.
   * @returns `true` si la etiqueta es válida, `false` en caso contrario.
   */
  verifyTag(message: Uint8Array, tag: Uint8Array): boolean {
    const expectedTag = this.generateTag(message, tag.length)

    // Comparación en tiempo constante para evitar ataques de temporización.
    if (tag.length !== expectedTag.length) {
      return false
    }

    let mismatch = 0
    for (let i = 0; i < tag.length; i++) {
      mismatch |= tag[i] ^ expectedTag[i]
    }

    return mismatch === 0
  }
}
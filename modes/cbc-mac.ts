import { AES } from "../aes"
import { xor } from "./utils/xor"

/**
 * Implementación del modo de operación AES-CBC-MAC (Cipher Block Chaining Message Authentication Code).
 *
 * CBC-MAC es un código de autenticación de mensajes basado en el modo CBC de AES.
 * Solo proporciona autenticación e integridad, no confidencialidad.
 *
 * Características principales:
 * - **Solo autenticación**: No cifra los datos, solo genera una etiqueta de autenticación.
 * - **Basado en CBC**: Utiliza el modo CBC para procesar los datos.
 * - **IV fijo**: Siempre utiliza un vector de inicialización de ceros.
 * - **Relleno**: Aplica relleno ISO-7816-4 cuando es necesario.
 *
 * Consideraciones de seguridad:
 * - **Solo para mensajes de longitud fija**: CBC-MAC básico solo es seguro para mensajes de longitud fija.
 * - **No para uso general**: Para mensajes de longitud variable, se debe usar CMAC (OMAC1).
 * - **Etiqueta corta**: Si se usa una etiqueta truncada, se reduce la seguridad.
 * - **Clave única**: La misma clave no debe usarse para CBC-MAC y CBC cifrante.
 *
 * CBC-MAC es la base para otros algoritmos MAC como CMAC y es utilizado en protocolos
 * como EMV, IEEE 802.11i y más.
 *
 * @example
 * ```typescript
 * const key = new Uint8Array(16); // Clave de 128 bits
 * const cbcMac = new ModeOfOperationCBC_MAC(key);
 * const message = new TextEncoder().encode("Mensaje a autenticar");
 * const tag = cbcMac.generateTag(message, 16); // Etiqueta de 16 bytes
 * const isValid = cbcMac.verifyTag(message, tag); // true
 * ```
 *
 * @see [NIST SP 800-38B](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf)
 * para la especificación oficial de CBC-MAC y CMAC.
 */
export class ModeOfOperationCBC_MAC {
  public readonly description = "CBC Message Authentication Code"
  public readonly name = "cbc-mac"

  private readonly aes: AES

  /**
   * Inicializa el modo de operación CBC-MAC con una clave.
   * @param key La clave de autenticación, debe ser de 16, 24 o 32 bytes (128, 192 o 256 bits).
   */
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
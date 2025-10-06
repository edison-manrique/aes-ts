import { AES } from "../aes"

/**
 * Implementación del modo de operación AES-CFB (Cipher Feedback).
 *
 * CFB es un modo de operación que convierte un cifrador de bloques en un cifrador de flujo.
 * Opera manteniendo un registro de desplazamiento que se cifra en cada paso, y el resultado
 * se utiliza para enmascarar el texto plano mediante XOR.
 *
 * Características principales:
 * - **Cifrador de flujo**: Puede cifrar datos de cualquier tamaño sin necesidad de relleno.
 * - **Autosincronización**: Puede recuperarse de errores de transmisión después de unos pocos bloques.
 * - **Tamaño de segmento configurable**: Puede procesar datos en segmentos de 1, 8 o 128 bits.
 * - **IV requerido**: Requiere un Vector de Inicialización único para cada operación de cifrado.
 *
 * Consideraciones de seguridad:
 * - **IV único**: El IV debe ser único para cada cifrado con la misma clave.
 * - **IV impredecible**: Para mayor seguridad, el IV debe ser impredecible (aleatorio).
 * - **Sin autenticación**: CFB no proporciona autenticación; se debe usar con un MAC para AE.
 * - **Error propagation**: Un bit erróneo en el texto cifrado afectará a varios bits en el texto plano descifrado.
 *
 * CFB es útil cuando se necesita un cifrado de flujo pero solo se dispone de un cifrador de bloques.
 * Ha sido reemplazado en gran medida por modos más modernos como CTR y AEAD.
 *
 * @example
 * ```typescript
 * const key = new Uint8Array(16); // Clave de 128 bits
 * const iv = new Uint8Array(16);  // Vector de inicialización de 128 bits
 * const cfb = new ModeOfOperationCFB(key, iv, 1); // CFB de 8 bits (1 byte)
 * const plaintext = new TextEncoder().encode("Mensaje secreto");
 * const ciphertext = cfb.encrypt(plaintext);
 * const decrypted = cfb.decrypt(ciphertext);
 * ```
 *
 * @see [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
 * para la especificación oficial del modo CFB.
 */
export class ModeOfOperationCFB {
  public readonly description = "Cipher Feedback"
  public readonly name = "cfb"
  private readonly aes: AES
  private readonly segmentSize: number
  private shiftRegister: Uint8Array

  /**
   * Inicializa el modo de operación CFB con una clave, un vector de inicialización opcional y un tamaño de segmento.
   * @param key La clave de cifrado, debe ser de 16, 24 o 32 bytes (128, 192 o 256 bits).
   * @param iv El vector de inicialización de 16 bytes. Si no se proporciona, se usa un bloque de ceros.
   * @param segmentSize El tamaño de segmento en bytes (1, 8 o 16 bytes). Por defecto es 1 byte.
   */
  constructor(key: Uint8Array, iv?: Uint8Array, segmentSize: number = 1) {
    this.aes = new AES(key)
    this.segmentSize = segmentSize

    if (iv && iv.length !== 16) {
      throw new Error("Tamaño de vector de inicialización inválido (debe ser 16 bytes)")
    }
    this.shiftRegister = iv ? new Uint8Array(iv) : new Uint8Array(16)
  }

  /**
   * Cifra datos en modo CFB.
   * @param plaintext El texto plano a cifrar. Su longitud debe ser múltiplo del tamaño de segmento.
   * @returns El texto cifrado del mismo tamaño que el texto plano.
   * @throws Error si la longitud del texto plano no es múltiplo del tamaño de segmento.
   */
  encrypt(plaintext: Uint8Array): Uint8Array {
    if (plaintext.length % this.segmentSize !== 0) {
      throw new Error(`Tamaño de texto plano inválido (debe ser múltiplo de segmentSize: ${this.segmentSize} bytes)`)
    }

    const ciphertext = new Uint8Array(plaintext)

    for (let i = 0; i < ciphertext.length; i += this.segmentSize) {
      const xorSegment = this.aes.encrypt(this.shiftRegister)

      // XOR del texto plano con el segmento cifrado para obtener el texto cifrado
      for (let j = 0; j < this.segmentSize; j++) {
        ciphertext[i + j] ^= xorSegment[j]
      }

      // Actualiza el registro de desplazamiento:
      // 1. Desplaza el registro a la izquierda
      this.shiftRegister.set(this.shiftRegister.subarray(this.segmentSize))
      // 2. Coloca el nuevo texto cifrado al final del registro
      this.shiftRegister.set(ciphertext.subarray(i, i + this.segmentSize), 16 - this.segmentSize)
    }

    return ciphertext
  }

  /**
   * Descifra datos en modo CFB.
   * @param ciphertext El texto cifrado a descifrar. Su longitud debe ser múltiplo del tamaño de segmento.
   * @returns El texto plano del mismo tamaño que el texto cifrado.
   * @throws Error si la longitud del texto cifrado no es múltiplo del tamaño de segmento.
   */
  decrypt(ciphertext: Uint8Array): Uint8Array {
    if (ciphertext.length % this.segmentSize !== 0) {
      throw new Error(`Tamaño de texto cifrado inválido (debe ser múltiplo de segmentSize: ${this.segmentSize} bytes)`)
    }

    const plaintext = new Uint8Array(ciphertext)

    for (let i = 0; i < plaintext.length; i += this.segmentSize) {
      const xorSegment = this.aes.encrypt(this.shiftRegister)

      // Guarda el segmento de texto cifrado actual ANTES de la operación XOR
      const currentCiphertextSegment = ciphertext.subarray(i, i + this.segmentSize)

      // XOR del texto cifrado con el segmento cifrado para obtener el texto plano
      for (let j = 0; j < this.segmentSize; j++) {
        plaintext[i + j] ^= xorSegment[j]
      }

      // Actualiza el registro de desplazamiento:
      // 1. Desplaza el registro a la izquierda
      this.shiftRegister.set(this.shiftRegister.subarray(this.segmentSize))
      // 2. Coloca el texto cifrado original al final del registro
      this.shiftRegister.set(currentCiphertextSegment, 16 - this.segmentSize)
    }

    return plaintext
  }
}
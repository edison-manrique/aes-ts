import { AES } from "../aes"

/**
 * Implementación del modo de operación AES-CBC (Cipher Block Chaining).
 *
 * CBC es un modo de operación que introduce dependencia entre bloques mediante
 * el encadenamiento de cada bloque de texto plano con el bloque cifrado anterior.
 * El primer bloque se combina con un Vector de Inicialización (IV).
 *
 * Características principales:
 * - **Encadenamiento**: Cada bloque de texto plano se XORea con el bloque cifrado anterior antes de cifrarse.
 * - **IV requerido**: Requiere un Vector de Inicialización único para cada operación de cifrado.
 * - **No paralelizable para cifrado**: Cada bloque debe esperar al cifrado del bloque anterior.
 * - **Paralelizable para descifrado**: Todos los bloques pueden descifrarse en paralelo.
 *
 * Consideraciones de seguridad:
 * - **IV único**: El IV debe ser único para cada cifrado con la misma clave.
 * - **IV impredecible**: Para mayor seguridad, el IV debe ser impredecible (aleatorio).
 * - **Sin autenticación**: CBC no proporciona autenticación; se debe usar con un MAC para AE.
 * - **Relleno requerido**: Requiere un esquema de relleno para datos que no son múltiplos de 16 bytes.
 *
 * CBC fue ampliamente usado en el pasado, pero ha sido reemplazado por modos AEAD como GCM.
 * Aún se encuentra en muchos sistemas heredados.
 *
 * @example
 * ```typescript
 * const key = new Uint8Array(16); // Clave de 128 bits
 * const iv = new Uint8Array(16);  // Vector de inicialización de 128 bits
 * const cbc = new ModeOfOperationCBC(key, iv);
 * const plaintext = new TextEncoder().encode("Mensaje secreto");
 * // Aplicar relleno PKCS#7 antes de cifrar
 * const ciphertext = cbc.encrypt(paddedPlaintext);
 * const decrypted = cbc.decrypt(ciphertext);
 * // Remover relleno después de descifrar
 * ```
 *
 * @see [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
 * para la especificación oficial del modo CBC.
 */
export class ModeOfOperationCBC {
  public readonly description = "Cipher Block Chaining"
  public readonly name = "cbc"
  private lastCipherblock: Uint8Array
  private readonly aes: AES

  /**
   * Inicializa el modo de operación CBC con una clave y un vector de inicialización opcional.
   * @param key La clave de cifrado, debe ser de 16, 24 o 32 bytes (128, 192 o 256 bits).
   * @param iv El vector de inicialización de 16 bytes. Si no se proporciona, se usa un bloque de ceros.
   */
  constructor(key: Uint8Array, iv?: Uint8Array) {
    if (iv && iv.length !== 16) {
      throw new Error("Tamaño de vector de inicialización inválido (debe ser 16 bytes)")
    }
    this.lastCipherblock = iv ? new Uint8Array(iv) : new Uint8Array(16)
    this.aes = new AES(key)
  }

  /**
   * Cifra un bloque o múltiples bloques de datos en modo CBC.
   * @param plaintext El texto plano a cifrar. Debe ser múltiplo de 16 bytes.
   * @returns El texto cifrado del mismo tamaño que el texto plano.
   * @throws Error si el tamaño del texto plano no es múltiplo de 16 bytes.
   */
  encrypt(plaintext: Uint8Array): Uint8Array {
    if (plaintext.length % 16 !== 0) {
      throw new Error("Tamaño de texto plano inválido (debe ser múltiplo de 16 bytes)")
    }

    const ciphertext = new Uint8Array(plaintext.length)
    for (let i = 0; i < plaintext.length; i += 16) {
      const block = plaintext.subarray(i, i + 16)
      for (let j = 0; j < 16; j++) {
        block[j] ^= this.lastCipherblock[j]
      }
      this.lastCipherblock = this.aes.encrypt(block)
      ciphertext.set(this.lastCipherblock, i)
    }
    return ciphertext
  }

  /**
   * Descifra un bloque o múltiples bloques de datos en modo CBC.
   * @param ciphertext El texto cifrado a descifrar. Debe ser múltiplo de 16 bytes.
   * @returns El texto plano del mismo tamaño que el texto cifrado.
   * @throws Error si el tamaño del texto cifrado no es múltiplo de 16 bytes.
   */
  decrypt(ciphertext: Uint8Array): Uint8Array {
    if (ciphertext.length % 16 !== 0) {
      throw new Error("Tamaño de texto cifrado inválido (debe ser múltiplo de 16 bytes)")
    }

    const plaintext = new Uint8Array(ciphertext.length)
    for (let i = 0; i < ciphertext.length; i += 16) {
      const block = ciphertext.subarray(i, i + 16)
      const decryptedBlock = this.aes.decrypt(block)
      for (let j = 0; j < 16; j++) {
        decryptedBlock[j] ^= this.lastCipherblock[j]
      }
      this.lastCipherblock = block
      plaintext.set(decryptedBlock, i)
    }
    return plaintext
  }
}
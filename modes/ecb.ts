import { AES } from "../aes"

/**
 * Implementación del modo de operación AES-ECB (Electronic Codebook).
 *
 * ECB es el modo de operación más simple para AES. Divide el texto plano en bloques
 * de 16 bytes y cifra cada bloque independientemente usando la misma clave.
 *
 * Características principales:
 * - **Simplicidad**: Es el modo más directo de usar.
 * - **Paralelización**: Todos los bloques pueden cifrarse/descifrarse en paralelo.
 * - **Determinismo**: El mismo bloque de texto plano siempre produce el mismo bloque de texto cifrado.
 *
 * Advertencias importantes:
 * - **No semánticamente seguro**: Patrones en el texto plano se reflejan en el texto cifrado.
 * - **No recomendado para uso general**: No debe usarse para datos sensibles sin contramedidas adicionales.
 * - **Vulnerable a ataques de reordenamiento**: Bloques pueden reordenarse sin detección.
 *
 * ECB debe evitarse en la mayoría de los casos prácticos. Se incluye principalmente
 * para completitud y para casos específicos donde los datos ya tienen una estructura
 * aleatoria inherente o se usan con técnicas adicionales de ofuscación.
 *
 * @example
 * ```typescript
 * const key = new Uint8Array(16); // Clave de 128 bits
 * const ecb = new ModeOfOperationECB(key);
 * const plaintext = new TextEncoder().encode("Mensaje de 16 bytes");
 * const ciphertext = ecb.encrypt(plaintext);
 * const decrypted = ecb.decrypt(ciphertext);
 * ```
 *
 * @see [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
 * para la especificación oficial del modo ECB.
 */
export class ModeOfOperationECB {
  public readonly description = "Electronic Codebook"
  public readonly name = "ecb"
  private readonly aes: AES

  /**
   * Inicializa el modo de operación ECB con una clave.
   * @param key La clave de cifrado, debe ser de 16, 24 o 32 bytes (128, 192 o 256 bits).
   */
  constructor(key: Uint8Array) {
    this.aes = new AES(key)
  }

  /**
   * Cifra un bloque o múltiples bloques de datos en modo ECB.
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
      const encryptedBlock = this.aes.encrypt(block)
      ciphertext.set(encryptedBlock, i)
    }
    return ciphertext
  }

  /**
   * Descifra un bloque o múltiples bloques de datos en modo ECB.
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
      plaintext.set(decryptedBlock, i)
    }
    return plaintext
  }
}
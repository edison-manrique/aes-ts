import { AES } from "../aes"

/**
 * Implementación del modo de operación AES-OFB (Output Feedback).
 *
 * OFB es un modo de operación que convierte un cifrador de bloques en un cifrador de flujo.
 * Opera generando una secuencia de claves pseudoaleatoria independiente del texto plano,
 * que luego se utiliza para enmascarar el texto plano mediante XOR.
 *
 * Características principales:
 * - **Cifrador de flujo**: Puede cifrar datos de cualquier tamaño sin necesidad de relleno.
 * - **Simétrico**: La operación de cifrado y descifrado es idéntica.
 * - **Paralelizable**: La secuencia de claves puede generarse por adelantado.
 * - **IV requerido**: Requiere un Vector de Inicialización único para cada operación de cifrado.
 *
 * Consideraciones de seguridad:
 * - **IV único**: El IV debe ser único para cada cifrado con la misma clave.
 * - **IV impredecible**: Para mayor seguridad, el IV debe ser impredecible (aleatorio).
 * - **Sin autenticación**: OFB no proporciona autenticación; se debe usar con un MAC para AE.
 * - **Error propagation**: Un bit erróneo en el texto cifrado afectará al mismo bit en el texto plano descifrado.
 * - **No debe reutilizarse**: La combinación clave+IV nunca debe reutilizarse.
 *
 * OFB es útil cuando se necesita un cifrado de flujo con una operación simétrica.
 * Ha sido reemplazado en gran medida por modos más modernos como CTR y AEAD.
 *
 * @example
 * ```typescript
 * const key = new Uint8Array(16); // Clave de 128 bits
 * const iv = new Uint8Array(16);  // Vector de inicialización de 128 bits
 * const ofb = new ModeOfOperationOFB(key, iv);
 * const plaintext = new TextEncoder().encode("Mensaje secreto");
 * const ciphertext = ofb.encrypt(plaintext);
 * const decrypted = ofb.decrypt(ciphertext); // ¡La misma operación!
 * ```
 *
 * @see [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
 * para la especificación oficial del modo OFB.
 */
export class ModeOfOperationOFB {
  public readonly description = "Output Feedback"
  public readonly name = "ofb"
  private readonly aes: AES
  private lastPrecipher: Uint8Array
  private lastPrecipherIndex: number

  /**
   * Inicializa el modo de operación OFB con una clave y un vector de inicialización opcional.
   * @param key La clave de cifrado, debe ser de 16, 24 o 32 bytes (128, 192 o 256 bits).
   * @param iv El vector de inicialización de 16 bytes. Si no se proporciona, se usa un bloque de ceros.
   */
  constructor(key: Uint8Array, iv?: Uint8Array) {
    this.aes = new AES(key)
    this.lastPrecipherIndex = 16

    if (iv && iv.length !== 16) {
      throw new Error("Tamaño de vector de inicialización inválido (debe ser 16 bytes)")
    }
    this.lastPrecipher = iv ? iv : new Uint8Array(16)
  }

  /**
   * Cifra o descifra datos en modo OFB. La misma operación se usa para ambos propósitos.
   * @param plaintext El texto plano a cifrar (o texto cifrado a descifrar).
   * @returns El texto cifrado (o texto plano) del mismo tamaño que la entrada.
   */
  encrypt(plaintext: Uint8Array): Uint8Array {
    const encrypted = new Uint8Array(plaintext)

    for (let i = 0; i < encrypted.length; i++) {
      if (this.lastPrecipherIndex === 16) {
        this.lastPrecipher = this.aes.encrypt(this.lastPrecipher)
        this.lastPrecipherIndex = 0
      }
      encrypted[i] ^= this.lastPrecipher[this.lastPrecipherIndex++]
    }

    return encrypted
  }

  /**
   * Descifra datos en modo OFB. Esta operación es idéntica a la de cifrado.
   * @param ciphertext El texto cifrado a descifrar.
   * @returns El texto plano del mismo tamaño que el texto cifrado.
   */
  // En OFB, la desencriptación es simétrica a la encriptación
  decrypt = this.encrypt
}
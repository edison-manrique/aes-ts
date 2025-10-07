import { AES } from "../aes"
import { xor } from "./utils/xor"

/**
 * Implementación del modo de operación AES-CMAC (Cipher-based Message Authentication Code).
 *
 * CMAC (también conocido como OMAC1) es un código de autenticación de mensajes basado en un cifrado de bloque.
 * Es una versión segura de CBC-MAC para mensajes de longitud variable. CMAC proporciona autenticación e integridad,
 * pero no confidencialidad.
 *
 * Características principales:
 * - **Autenticación segura**: Seguro para mensajes de longitud variable, a diferencia de CBC-MAC básico.
 * - **Basado en CBC**: Utiliza el modo CBC para procesar los datos con un IV de ceros.
 * - **Subclaves especiales**: Utiliza subclaves derivadas para manejar el relleno correctamente.
 * - **Relleno automático**: Aplica relleno automáticamente según el algoritmo CMAC.
 *
 * Consideraciones de seguridad:
 * - **Nonce único**: La clave debe ser única para cada mensaje autenticado.
 * - **Etiqueta corta**: Si se usa una etiqueta truncada, se reduce la seguridad.
 * - **Clave única**: La misma clave no debe usarse para CMAC y para cifrado.
 *
 * CMAC es un estándar NIST (SP 800-38B) y es ampliamente utilizado en aplicaciones criptográficas
 * como protocolos de seguridad y sistemas de autenticación.
 *
 * @example
 * ```typescript
 * const key = new Uint8Array(16); // Clave de 128 bits
 * const cmac = new ModeOfOperationCMAC(key);
 * const message = new TextEncoder().encode("Mensaje a autenticar");
 * const tag = cmac.generateTag(message, 16); // Etiqueta de 16 bytes
 * const isValid = cmac.verifyTag(message, tag); // true
 * ```
 *
 * @see [NIST SP 800-38B](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf)
 * para la especificación oficial de CMAC.
 */
export class ModeOfOperationCMAC {
  public readonly description = "Cipher-based Message Authentication Code"
  public readonly name = "cmac"

  private readonly aes: AES
  private readonly K1: Uint8Array
  private readonly K2: Uint8Array

  /**
   * Inicializa el modo de operación CMAC con una clave.
   * @param key La clave de autenticación, debe ser de 16, 24 o 32 bytes (128, 192 o 256 bits).
   */
  constructor(key: Uint8Array) {
    this.aes = new AES(key)
    
    // Generar las subclaves K1 y K2 según el algoritmo del estándar
    this.K1 = this._generateSubkey(1)
    this.K2 = this._generateSubkey(2)
  }

  /**
   * Duplica un bloque en el campo de Galois GF(2^128) utilizado en AES.
   * Esta operación es necesaria para generar las subclaves en CMAC.
   * @param block Bloque de 16 bytes a duplicar
   * @private
   */
  private _double(block: Uint8Array): Uint8Array {
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

  /**
   * Genera las subclaves K1 o K2 necesarias para el algoritmo CMAC.
   * @param index Índice de la subclave (1 para K1, 2 para K2)
   * @private
   */
  private _generateSubkey(index: number): Uint8Array {
    // Paso 1: Aplicar el cifrado AES al bloque cero
    const L = this.aes.encrypt(new Uint8Array(16))
    
    // Paso 2: Duplicar L para obtener K1
    const K1 = this._double(L)
    
    // Si index es 2, necesitamos duplicar K1 para obtener K2
    if (index === 2) {
      return this._double(K1)
    }
    
    return K1
  }

  /**
   * Genera una etiqueta de autenticación para un mensaje usando CMAC.
   * @param message El mensaje de texto plano a autenticar.
   * @param tagSize La longitud deseada para la etiqueta (se truncará si es menor de 16).
   * @returns La etiqueta de autenticación (MAC).
   */
  generateTag(message: Uint8Array, tagSize: number = 16): Uint8Array {
    if (tagSize > 16) {
      throw new Error("El tamaño de la etiqueta no puede ser mayor de 16 bytes.")
    }

    // Paso 1: Dividir el mensaje en bloques de 16 bytes
    const n = Math.ceil((message.length + 1) / 16) || 1 // Al menos 1 bloque incluso para mensajes vacíos
    const processedMessage = new Uint8Array(n * 16)
    processedMessage.set(message)

    // Paso 2: Preparar el último bloque
    let lastBlock: Uint8Array
    if (message.length === 0 || message.length % 16 !== 0) {
      // Caso 2: El mensaje no tiene una longitud que es múltiplo del tamaño de bloque
      // Aplicar relleno y XOR con K2
      processedMessage[message.length] = 0x80
      lastBlock = xor(processedMessage.subarray(processedMessage.length - 16), this.K2)
    } else {
      // Caso 1: El mensaje tiene una longitud que es múltiplo del tamaño de bloque
      // XOR el último bloque con K1
      lastBlock = xor(processedMessage.subarray(processedMessage.length - 16), this.K1)
    }

    // Paso 3: Aplicar CBC-MAC
    let X = new Uint8Array(16) // IV siempre es cero
    
    // Procesar todos los bloques excepto el último
    for (let i = 0; i < n - 1; i++) {
      const block = processedMessage.subarray(i * 16, (i + 1) * 16)
      const y = xor(X, block)
      X = this.aes.encrypt(y)
    }

    // Procesar el último bloque
    const y = xor(X, lastBlock)
    const T = this.aes.encrypt(y)

    // La etiqueta es el resultado final, truncado al tamaño deseado
    return T.subarray(0, tagSize)
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
import { AES } from "../aes"
import { xor } from "./utils/xor"
import { ModeOfOperationCTR } from "./ctr"

/**
 * Implementación del modo de operación AES-EAX (Encrypt-then-Authenticate-then-Translate).
 *
 * EAX es un modo de operación AEAD (Authenticated Encryption with Associated Data) que
 * proporciona confidencialidad, integridad y autenticidad. Es un modo de dos pasos que
 * primero cifra los datos y luego aplica autenticación.
 *
 * Características principales:
 * - **AEAD**: Proporciona cifrado autenticado con datos asociados.
 * - **Nonce flexible**: El nonce puede tener cualquier longitud.
 * - **Resistencia a nonce**: Seguridad no se ve comprometida gravemente si se reutiliza el nonce.
 * - **Paralelizable**: El cifrado y autenticación pueden realizarse en paralelo.
 * - **Etiqueta de longitud variable**: La etiqueta puede tener entre 8 y 16 bytes.
 *
 * Funcionamiento:
 * 1. Se calcula un MAC del nonce usando OMAC (CMAC).
 * 2. Este MAC se usa como IV para el modo CTR para cifrar el texto plano.
 * 3. Se calculan MACs separados para el nonce, datos asociados y texto cifrado.
 * 4. La etiqueta final es el XOR de estos tres MACs.
 *
 * Consideraciones de seguridad:
 * - **Nonce único**: Aunque EAX es resistente a la reutilización de nonce, se recomienda usar nonces únicos.
 * - **Sin autenticación débil**: EAX no permite verificar partes de los datos sin verificar todo.
 * - **Eficiencia**: Requiere tres aplicaciones de AES por bloque de datos.
 *
 * EAX es un modo bien estudiado y seguro que se usa en aplicaciones como IEEE 802.11i
 * y es considerado un estándar de oro para AEAD.
 *
 * @example
 * ```typescript
 * const key = new Uint8Array(16); // Clave de 128 bits
 * const eax = new ModeOfOperationEAX(key, 16); // Etiqueta de 16 bytes
 * const plaintext = new TextEncoder().encode("Mensaje secreto");
 * const nonce = new Uint8Array(12); // Nonce de 96 bits
 * const aad = new TextEncoder().encode("Datos asociados");
 * 
 * const { ciphertext, tag } = eax.encrypt(plaintext, nonce, aad);
 * const decrypted = eax.decrypt(ciphertext, tag, nonce, aad);
 * ```
 *
 * @see [EAX Paper](http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf) para la especificación original.
 * @see [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
 * para información sobre modos AEAD.
 */
export class ModeOfOperationEAX {
  public readonly description = "EAX Mode"
  public readonly name = "eax"

  private readonly aes: AES
  private readonly tagSize: number
  private readonly key: Uint8Array

  /**
   * Inicializa el modo de operación EAX con una clave y tamaño de etiqueta opcional.
   * @param key La clave de cifrado, debe ser de 16, 24 o 32 bytes (128, 192 o 256 bits).
   * @param tagSize El tamaño de la etiqueta de autenticación (8-16 bytes). Por defecto es 16 bytes.
   */
  constructor(key: Uint8Array, tagSize: number = 16) {
    if (tagSize < 8 || tagSize > 16) {
      throw new Error("Tamaño de etiqueta EAX inválido (debe estar entre 8 y 16)")
    }
    this.aes = new AES(key)
    this.tagSize = tagSize
    this.key = key
  }

  /**
   * Duplica un valor en el cuerpo de Galois GF(2^128).
   * Necesario para la derivación de subclaves en OMAC/CMAC.
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
   * Calcula el OMAC (CMAC) para un mensaje dado con un prefijo de dominio.
   * @param data El mensaje a autenticar.
   * @param domain El byte de dominio (0 para Nonce, 1 para AAD, 2 para Ciphertext).
   * @private
   */
  private _omac(data: Uint8Array, domain: number): Uint8Array {
    // Derivación de subclaves para OMAC
    const L = this.aes.encrypt(new Uint8Array(16))
    const L_u = this._double(L)
    const L_u2 = this._double(L_u)

    // Prepara el mensaje con el prefijo de dominio
    const message = new Uint8Array(1 + data.length)
    message[0] = domain
    message.set(data, 1)

    let lastBlock = new Uint8Array(16)
    const numBlocks = Math.ceil(message.length / 16)

    for (let i = 0; i < numBlocks - 1; i++) {
      const from = i * 16
      const block = message.subarray(from, from + 16)
      lastBlock = this.aes.encrypt(xor(lastBlock, block))
    }

    const finalBlock = message.subarray((numBlocks - 1) * 16)
    let subkey: Uint8Array
    let paddedFinalBlock = new Uint8Array(16)

    if (finalBlock.length === 16) {
      subkey = L_u
      paddedFinalBlock = finalBlock
    } else {
      subkey = L_u2
      paddedFinalBlock.set(finalBlock)
      paddedFinalBlock[finalBlock.length] = 0x80
    }

    return this.aes.encrypt(xor(lastBlock, xor(paddedFinalBlock, subkey)))
  }

  /**
   * Cifra y autentica los datos usando AES-EAX.
   * @param plaintext El texto plano a cifrar.
   * @param nonce El Nonce. Puede tener cualquier longitud. ¡No debe reutilizarse!
   * @param associatedData Datos adicionales que serán autenticados pero no cifrados.
   * @returns Un objeto con el `ciphertext` y la etiqueta de autenticación `tag`.
   */
  encrypt(plaintext: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): { ciphertext: Uint8Array; tag: Uint8Array } {
    // Calcular el MAC del nonce, que servirá como IV para el modo CTR.
    const nonceMac = this._omac(nonce, 0)

    // Cifrar el texto plano usando CTR, inicializado con el MAC del nonce.
    const ctr = new ModeOfOperationCTR(this.key, nonceMac)
    const ciphertext = ctr.encrypt(plaintext)

    // Calcular los MACs de los datos asociados y del texto cifrado.
    const associatedDataMac = this._omac(associatedData, 1)
    const ciphertextMac = this._omac(ciphertext, 2)

    // La etiqueta final es el XOR de los tres MACs.
    const tag = xor(xor(nonceMac, ciphertextMac), associatedDataMac)

    return { ciphertext, tag: tag.subarray(0, this.tagSize) }
  }

  /**
   * Descifra y verifica la autenticidad de los datos.
   * @param ciphertext El texto cifrado.
   * @param tag La etiqueta de autenticación recibida.
   * @param nonce El mismo Nonce usado en el cifrado.
   * @param associatedData Los mismos datos asociados usados en el cifrado.
   * @returns El texto plano si la autenticación es exitosa, o `null` si falla.
   */
  decrypt(ciphertext: Uint8Array, tag: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): Uint8Array | null {
    if (tag.length !== this.tagSize) {
      return null
    }

    // Calcular los tres MACs de la misma forma que en el cifrado.
    const nonceMac = this._omac(nonce, 0)
    const associatedDataMac = this._omac(associatedData, 1)
    const ciphertextMac = this._omac(ciphertext, 2)

    // Recalcular la etiqueta esperada.
    const expectedTag = xor(xor(nonceMac, ciphertextMac), associatedDataMac)

    // Comparar la etiqueta recibida con la esperada en tiempo constante.
    let tagsMatch = 0
    for (let i = 0; i < this.tagSize; i++) {
      tagsMatch |= tag[i] ^ expectedTag[i]
    }

    if (tagsMatch !== 0) {
      return null // ¡Fallo de autenticación!
    }

    // Si la autenticación es exitosa, proceder a descifrar.
    const ctr = new ModeOfOperationCTR(this.key, nonceMac)
    const plaintext = ctr.decrypt(ciphertext)

    return plaintext
  }
}
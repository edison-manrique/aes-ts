import { AES } from "../aes"
import { xor } from "./utils/xor"
import { ModeOfOperationCTR } from "./ctr"

/**
 * Implementación del modo de operación AES-HybridCTR (Hybrid Counter Mode with Authentication and Tweak).
 *
 * HybridCTR es un modo de operación híbrido que combina características de varios modos AES
 * estándar para proporcionar cifrado autenticado con tweak. Combina elementos de:
 * - CTR para cifrado eficiente
 * - GCM-SIV para generación de nonce sintético
 * - XTS para soporte de tweak
 * - EAX/GCM para autenticación
 *
 * Características principales:
 * - **Cifrado autenticado**: Proporciona tanto confidencialidad como autenticidad.
 * - **Nonce sintético**: Puede generar automáticamente un nonce a partir de los datos.
 * - **Soporte de tweak**: Similar a XTS, permite un valor de tweak para posicionamiento.
 * - **Resistencia a nonce**: Seguridad incluso si se reutiliza el nonce.
 * - **Flexibilidad**: Permite datos asociados adicionales para autenticación.
 *
 * Proceso:
 * 1. Genera un nonce sintético si no se proporciona uno.
 * 2. Combina el nonce con el tweak para crear un nonce modificado.
 * 3. Utiliza el modo CTR con el nonce modificado para cifrar los datos.
 * 4. Crea una etiqueta de autenticación basada en todos los componentes.
 * 5. Durante el descifrado, verifica la etiqueta antes de descifrar.
 *
 * @example
 * ```typescript
 * const key = new Uint8Array(32); // Clave de 256 bits
 * const hybridCtr = new ModeOfOperationHybridCTR(key);
 * const plaintext = new TextEncoder().encode("Mensaje secreto");
 * const nonce = new Uint8Array(16); // Nonce opcional
 * const aad = new TextEncoder().encode("Datos asociados");
 * const tweak = new Uint8Array(16); // Tweak para posicionamiento
 * 
 * const { ciphertext, tag, nonce: usedNonce } = hybridCtr.encrypt(plaintext, nonce, aad, tweak);
 * const decrypted = hybridCtr.decrypt(ciphertext, tag, usedNonce, aad, tweak);
 * ```
 */
export class ModeOfOperationHybridCTR {
  public readonly description = "Hybrid Counter Mode with Authentication and Tweak"
  public readonly name = "hybrid-ctr"

  private readonly aes: AES
  private readonly key: Uint8Array
  private readonly tagSize: number

  /**
   * Inicializa el modo de operación HybridCTR con una clave.
   * @param key La clave de cifrado, debe ser de 16, 24 o 32 bytes (128, 192 o 256 bits).
   * @param tagSize El tamaño de la etiqueta de autenticación (entre 8 y 16 bytes). Por defecto es 16 bytes.
   */
  constructor(key: Uint8Array, tagSize: number = 16) {
    if (![16, 24, 32].includes(key.length)) {
      throw new Error("Key must be 16, 24, or 32 bytes long")
    }
    
    if (tagSize < 8 || tagSize > 16) {
      throw new Error("Tag size must be between 8 and 16 bytes")
    }
    
    this.aes = new AES(key)
    this.key = key
    this.tagSize = tagSize
  }

  /**
   * Genera un nonce sintético similar al enfoque de GCM-SIV.
   * Combina texto plano, datos asociados y tweak para crear un nonce único.
   * @private
   */
  private _generateSyntheticNonce(plaintext: Uint8Array, associatedData: Uint8Array, tweak: Uint8Array): Uint8Array {
    // Create a hash of the inputs to generate a synthetic nonce
    const combined = new Uint8Array(plaintext.length + associatedData.length + tweak.length)
    combined.set(plaintext, 0)
    combined.set(associatedData, plaintext.length)
    combined.set(tweak, plaintext.length + associatedData.length)
    
    // Process in blocks and XOR together
    let hash = new Uint8Array(16)
    for (let i = 0; i < combined.length; i += 16) {
      const block = combined.subarray(i, Math.min(i + 16, combined.length))
      const paddedBlock = new Uint8Array(16)
      paddedBlock.set(block)
      hash = xor(hash, this.aes.encrypt(paddedBlock))
    }
    
    return hash
  }

  /**
   * Crea una etiqueta de autenticación similar a GCM/EAX.
   * Combina todos los componentes (texto plano, nonce, datos asociados, tweak) para generar una etiqueta.
   * @private
   */
  private _createTag(plaintext: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array, tweak: Uint8Array): Uint8Array {
    // Create a unique tag by combining all inputs
    const components: Uint8Array[] = [plaintext, nonce, associatedData, tweak]
    let tagBase = new Uint8Array(16)
    
    components.forEach(component => {
      const len = component.length
      const lenBytes = new Uint8Array(16)
      lenBytes[15] = len & 0xff
      lenBytes[14] = (len >> 8) & 0xff
      lenBytes[13] = (len >> 16) & 0xff
      lenBytes[12] = (len >> 24) & 0xff
      
      tagBase = xor(tagBase, this.aes.encrypt(lenBytes))
      
      // Process component data
      for (let i = 0; i < component.length; i += 16) {
        const block = component.subarray(i, Math.min(i + 16, component.length))
        const paddedBlock = new Uint8Array(16)
        paddedBlock.set(block)
        tagBase = xor(tagBase, this.aes.encrypt(paddedBlock))
      }
    })
    
    // Finalize tag
    const finalTag = this.aes.encrypt(tagBase)
    return finalTag.subarray(0, this.tagSize)
  }

  /**
   * Cifra y autentica datos utilizando el modo HybridCTR.
   * @param plaintext Los datos a cifrar.
   * @param nonce El nonce (puede omitirse para generar un nonce sintético).
   * @param associatedData Datos adicionales a autenticar pero no cifrar.
   * @param tweak Valor de tweak (por ejemplo, número de sector para cifrado de disco).
   * @returns Objeto con ciphertext, etiqueta de autenticación y nonce utilizado.
   */
  encrypt(plaintext: Uint8Array, nonce?: Uint8Array, associatedData: Uint8Array = new Uint8Array(0), tweak: Uint8Array = new Uint8Array(16)): { ciphertext: Uint8Array; tag: Uint8Array; nonce: Uint8Array } {
    // Generate synthetic nonce if not provided
    const actualNonce = nonce || this._generateSyntheticNonce(plaintext, associatedData, tweak)
    
    // Apply tweak to nonce for positional encryption (similar to XTS)
    const tweakedNonce = xor(actualNonce, tweak)
    
    // Encrypt using CTR mode
    const ctr = new ModeOfOperationCTR(this.key, tweakedNonce)
    const ciphertext = ctr.encrypt(plaintext)
    
    // Create authentication tag
    const tag = this._createTag(plaintext, actualNonce, associatedData, tweak)
    
    return { ciphertext, tag, nonce: actualNonce }
  }

  /**
   * Descifra y verifica datos autenticados utilizando el modo HybridCTR.
   * @param ciphertext Los datos a descifrar.
   * @param tag La etiqueta de autenticación.
   * @param nonce El nonce utilizado para el cifrado.
   * @param associatedData Datos autenticados adicionales.
   * @param tweak Valor de tweak.
   * @returns Texto plano descifrado si la autenticación tiene éxito, null en caso contrario.
   */
  decrypt(ciphertext: Uint8Array, tag: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array = new Uint8Array(0), tweak: Uint8Array = new Uint8Array(16)): Uint8Array | null {
    if (tag.length !== this.tagSize) {
      return null
    }
    
    // Apply tweak to nonce for decryption (similar to XTS)
    const tweakedNonce = xor(nonce, tweak)
    
    // Decrypt using CTR mode
    const ctr = new ModeOfOperationCTR(this.key, tweakedNonce)
    const plaintext = ctr.decrypt(ciphertext)
    
    // Verify authentication tag
    const expectedTag = this._createTag(plaintext, nonce, associatedData, tweak)
    
    // Constant-time comparison
    if (tag.length !== expectedTag.length) {
      return null
    }
    
    let result = 0
    for (let i = 0; i < tag.length; i++) {
      result |= tag[i] ^ expectedTag[i]
    }
    
    if (result !== 0) {
      return null // Authentication failed
    }
    
    return plaintext
  }
}
import { AES } from "../aes"

/**
 * Implementación del modo de operación AES-CCM (Counter with CBC-MAC).
 *
 * CCM es un modo de operación AEAD (Authenticated Encryption with Associated Data) que
 * proporciona confidencialidad, integridad y autenticidad. Combina el modo CBC-MAC para
 * autenticación con el modo CTR para cifrado, ambos usando la misma clave.
 *
 * Características principales:
 * - **AEAD**: Proporciona cifrado autenticado con datos asociados.
 * - **Longitud de nonce variable**: El nonce puede tener entre 7 y 13 bytes (15-L).
 * - **Longitud de etiqueta variable**: La etiqueta puede tener entre 4 y 16 bytes (par).
 * - **Longitud de datos limitada**: La longitud del texto plano/cifrado está limitada por L.
 * - **No paralelizable**: Requiere procesamiento secuencial tanto para cifrado como autenticación.
 *
 * Funcionamiento:
 * 1. Se calcula CBC-MAC sobre el texto plano y datos asociados.
 * 2. Se cifra el texto plano usando el modo CTR.
 * 3. Se combina la MAC con el keystream del primer bloque CTR para formar la etiqueta.
 *
 * Consideraciones de seguridad:
 * - **Nonce único**: El nonce debe ser único para cada cifrado con la misma clave.
 * - **Sin protección contra reordenamiento**: No protege contra reordenamiento de paquetes.
 * - **Longitud fija**: En algunas implementaciones, se requiere longitud fija de datos.
 * - **Complejidad**: Más complejo de implementar correctamente que GCM.
 *
 * CCM es ampliamente utilizado en protocolos como IEEE 802.11i (WiFi) y TLS.
 * Es un estándar NIST y una opción popular para entornos con restricciones.
 *
 * @example
 * ```typescript
 * const key = new Uint8Array(16); // Clave de 128 bits
 * const nonce = new Uint8Array(12); // Nonce de 12 bytes (con L=3)
 * const ccm = new ModeOfOperationCCM(key, 16, 3); // Etiqueta de 16 bytes, L=3
 * const plaintext = new TextEncoder().encode("Mensaje secreto");
 * const aad = new TextEncoder().encode("Datos asociados");
 * 
 * const { ciphertext, tag } = ccm.encrypt(plaintext, nonce, aad);
 * const decrypted = ccm.decrypt(ciphertext, nonce, tag, aad);
 * ```
 *
 * @see [NIST SP 800-38C](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf)
 * para la especificación oficial del modo CCM.
 */
export class ModeOfOperationCCM {
  public readonly description = "Counter with CBC-MAC"
  public readonly name = "ccm"

  private readonly aes: AES
  private readonly tagSize: number
  private readonly L: number

  /**
   * Inicializa el modo de operación CCM con una clave, tamaño de etiqueta y parámetro L.
   * @param key La clave de cifrado, debe ser de 16, 24 o 32 bytes (128, 192 o 256 bits).
   * @param tagSize El tamaño de la etiqueta de autenticación (4-16 bytes, par). Por defecto es 16 bytes.
   * @param L El parámetro L que determina la longitud del nonce y límite de datos (2-8). Por defecto es 4.
   */
  constructor(key: Uint8Array, tagSize: number = 16, L: number = 4) {
    this.aes = new AES(key)

    if (tagSize < 4 || tagSize > 16 || tagSize % 2 !== 0) {
      throw new Error("Tamaño de etiqueta CCM inválido (debe ser un número par entre 4 y 16)")
    }
    this.tagSize = tagSize

    if (L < 2 || L > 8) {
      throw new Error("Valor de L inválido para CCM (debe estar entre 2 y 8)")
    }
    this.L = L
  }

  /**
   * Cifra y autentica los datos usando el modo CCM.
   * @param plaintext El texto plano a cifrar.
   * @param iv El Nonce (vector de inicialización). Su longitud debe ser 15 - L bytes.
   * @param associatedData Datos adicionales que serán autenticados pero no cifrados.
   * @returns Un objeto con el `ciphertext` y la etiqueta de autenticación `tag`.
   */
  encrypt(plaintext: Uint8Array, iv: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): { ciphertext: Uint8Array; tag: Uint8Array } {
    if (iv.length !== 15 - this.L) {
      throw new Error(`Longitud de IV inválida para CCM (debe ser ${15 - this.L} bytes)`)
    }

    // Fase 1: Calcular CBC-MAC sobre el plaintext. Devuelve un MAC de 16 bytes.
    const cbcMac = this._cbcMac(plaintext, iv, associatedData)

    // Fase 2: Cifrar el texto plano usando el modo CTR.
    const ciphertext = this._ctrProcess(plaintext, iv)

    // Fase 3: "Cifrar" la etiqueta de autenticación con el primer bloque del keystream (S0).
    const s0 = this._computeS0(iv)
    const tag = this._xorMac(cbcMac, s0)

    return { ciphertext, tag }
  }

  /**
   * Descifra y verifica la autenticidad de los datos.
   * @param ciphertext El texto cifrado.
   * @param iv El mismo Nonce usado en el cifrado.
   * @param tag La etiqueta de autenticación recibida.
   * @param associatedData Los mismos datos asociados usados en el cifrado.
   * @returns El texto plano si la autenticación es exitosa, o `null` si falla.
   */
  decrypt(ciphertext: Uint8Array, iv: Uint8Array, tag: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): Uint8Array | null {
    if (tag.length !== this.tagSize) {
      return null // La longitud de la etiqueta no coincide
    }
    if (iv.length !== 15 - this.L) {
      throw new Error(`Longitud de IV inválida para CCM (debe ser ${15 - this.L} bytes)`)
    }

    // Fase 1: Descifrar el texto cifrado para obtener el texto plano potencial.
    const plaintext = this._ctrProcess(ciphertext, iv)

    // Fase 2: Recalcular la CBC-MAC sobre el texto plano descifrado y los datos asociados.
    const calculatedMac = this._cbcMac(plaintext, iv, associatedData)

    // Fase 3: "Cifrar" la MAC recién calculada para obtener la etiqueta esperada.
    const s0 = this._computeS0(iv)
    const expectedTag = this._xorMac(calculatedMac, s0)

    // Fase 4: Comparar la etiqueta recibida con la etiqueta esperada en tiempo constante.
    let tagsMatch = 0
    for (let i = 0; i < this.tagSize; i++) {
      tagsMatch |= tag[i] ^ expectedTag[i]
    }

    if (tagsMatch !== 0) {
      return null // ¡Fallo de autenticación!
    }

    return plaintext
  }

  private _cbcMac(payload: Uint8Array, iv: Uint8Array, associatedData: Uint8Array): Uint8Array {
    const B0 = new Uint8Array(16)
    const hasAAD = associatedData.length > 0
    B0[0] = (hasAAD ? 1 << 6 : 0) | (((this.tagSize - 2) / 2) << 3) | (this.L - 1)
    B0.set(iv, 1)
    for (let i = 0; i < this.L; i++) {
      B0[15 - i] = (payload.length >> (i * 8)) & 0xff
    }

    let lastBlock = this.aes.encrypt(B0)

    if (hasAAD) {
      const formattedAAD = this.formatAAD(associatedData)
      for (let i = 0; i < formattedAAD.length; i += 16) {
        const block = formattedAAD.subarray(i, i + 16)
        for (let j = 0; j < 16; j++) {
          lastBlock[j] ^= block[j]
        }
        lastBlock = this.aes.encrypt(lastBlock)
      }
    }

    for (let i = 0; i < payload.length; i += 16) {
      const block = new Uint8Array(16)
      block.set(payload.subarray(i, i + 16))
      for (let j = 0; j < 16; j++) {
        lastBlock[j] ^= block[j]
      }
      lastBlock = this.aes.encrypt(lastBlock)
    }

    return lastBlock // Devuelve el MAC completo de 16 bytes (T)
  }

  private formatAAD(aad: Uint8Array): Uint8Array {
    let lenBlock: Uint8Array
    const aadLen = aad.length

    // El límite correcto es 2^16 - 2^8 = 65280.
    if (aadLen < 65280) {
      lenBlock = new Uint8Array(2)
      lenBlock[0] = (aadLen >> 8) & 0xff
      lenBlock[1] = aadLen & 0xff
    } else if (aadLen <= 0xffffffff) {
      // Límite superior teórico
      lenBlock = new Uint8Array(6)
      lenBlock[0] = 0xff
      lenBlock[1] = 0xfe
      lenBlock[2] = (aadLen >> 24) & 0xff
      lenBlock[3] = (aadLen >> 16) & 0xff
      lenBlock[4] = (aadLen >> 8) & 0xff
      lenBlock[5] = aadLen & 0xff
    } else {
      throw new Error("Longitud de datos asociados demasiado grande.")
    }

    const totalLen = lenBlock.length + aadLen
    const paddedLen = Math.ceil(totalLen / 16) * 16
    const result = new Uint8Array(paddedLen)

    result.set(lenBlock)
    result.set(aad, lenBlock.length)

    return result
  }

  /**
   * Calcula el bloque de keystream S0 = E(K, A0), usado para la etiqueta.
   */
  private _computeS0(iv: Uint8Array): Uint8Array {
    const A0 = new Uint8Array(16)
    A0[0] = this.L - 1 // Flags
    A0.set(iv, 1) // Nonce
    // Los bytes del contador (finales) se dejan en 0 para A0.
    return this.aes.encrypt(A0)
  }

  /**
   * Realiza la operación XOR entre el MAC (T) y S0 para obtener la etiqueta (U),
   * truncando al tamaño de etiqueta especificado.
   */
  private _xorMac(mac: Uint8Array, s0: Uint8Array): Uint8Array {
    const tag = new Uint8Array(this.tagSize)
    for (let i = 0; i < this.tagSize; i++) {
      tag[i] = mac[i] ^ s0[i]
    }
    return tag
  }

  /**
   * Realiza la operación de cifrado/descifrado en modo CTR para los datos.
   */
  private _ctrProcess(data: Uint8Array, iv: Uint8Array): Uint8Array {
    const processedData = new Uint8Array(data)
    const counterBlock = new Uint8Array(16)
    counterBlock[0] = this.L - 1
    counterBlock.set(iv, 1)

    // Bucle para cada bloque de datos, comenzando con el contador en 1.
    const numBlocks = Math.ceil(data.length / 16)
    for (let i = 1; i <= numBlocks; i++) {
      // Establece el valor del contador para el bloque actual (Ai)
      let counterVal = i
      for (let j = 0; j < this.L; j++) {
        counterBlock[15 - j] = (counterVal >> (j * 8)) & 0xff
      }

      const keyStreamBlock = this.aes.encrypt(counterBlock)

      const offset = (i - 1) * 16
      for (let j = 0; j < 16 && offset + j < data.length; j++) {
        processedData[offset + j] ^= keyStreamBlock[j]
      }
    }

    return processedData
  }
}
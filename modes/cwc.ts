import { AES } from "../aes"
import { Counter, ModeOfOperationCTR } from "./ctr"

/**
 * Representa una implementación del modo de operación AES-CWC (Carter-Wegman + Counter).
 *
 * CWC es un esquema de Cifrado Autenticado con Datos Asociados (AEAD) que
 * sigue el paradigma "Encrypt-then-MAC". Este enfoque es altamente seguro y
 * resistente a ataques de texto cifrado elegido.
 *
 * El proceso se divide en dos fases principales:
 * 1.  **Cifrado**: El texto plano se cifra utilizando el modo Counter (CTR) para
 * producir el texto cifrado. El contador se inicializa con un nonce único.
 * 2.  **Autenticación**: Se calcula una etiqueta de autenticación (MAC) sobre
 * el texto cifrado resultante y los datos asociados (AAD). Esto se logra
 * mediante un hash universal (POLYVAL) y el cifrado del nonce.
 *
 * Características principales:
 * - **Seguridad**: Proporciona confidencialidad, autenticidad e integridad.
 * - **Eficiencia**: El cifrado y la autenticación se realizan en paralelo.
 * - **Resistencia a Nonce**: No requiere un nonce completamente aleatorio, aunque
 * se recomienda su unicidad para cada operación de cifrado.
 *
 * @example
 * ```typescript
 * const key = new Uint8Array(32); // Clave de 256 bits
 * const cwc = new ModeOfOperationCWC(key);
 * const plaintext = new TextEncoder().encode("Mensaje secreto");
 * const nonce = new Uint8Array(16); // 128-bit nonce
 * const aad = new TextEncoder().encode("Datos asociados");
 * 
 * const { ciphertext, tag } = cwc.encrypt(plaintext, nonce, aad);
 * const decrypted = cwc.decrypt(ciphertext, tag, nonce, aad);
 * ```
 */
export class ModeOfOperationCWC {
  public readonly description = "Carter-Wegman + Counter Mode (Encrypt-then-MAC)"
  public readonly name = "cwc"

  private readonly masterKey: Uint8Array
  private readonly aes: AES

  /**
   * Inicializa el modo de operación CWC con una clave maestra.
   * @param key La clave maestra, que debe ser de 16 bytes (AES-128) o 32 bytes (AES-256).
   */
  constructor(key: Uint8Array) {
    if (key.length !== 16 && key.length !== 32) {
      throw new Error("Tamaño de clave inválido para CWC (debe ser 16 o 32 bytes)")
    }
    this.masterKey = key
    this.aes = new AES(this.masterKey)
  }

  /**
   * Multiplicación en el cuerpo de Galois GF(2^128) para POLYVAL.
   * Esta es la función de hash universal en el núcleo del MAC de Carter-Wegman.
   * El polinomio irreducible es x^128 + x^127 + x^126 + x^121 + 1.
   * @private
   */
  private polyvalMultiply(x: Uint8Array, y: Uint8Array): Uint8Array<ArrayBuffer> {
    const z = new Uint8Array(16)
    let v = new Uint8Array(y)

    for (let i = 0; i < 128; i++) {
      const xByteIndex = Math.floor(i / 8)
      const xBitIndex = 7 - (i % 8)

      // Si el bit 'i' de 'x' está activado, z ^= v
      if ((x[xByteIndex] >> xBitIndex) & 1) {
        for (let j = 0; j < 16; j++) {
          z[j] ^= v[j]
        }
      }

      // Desplaza 'v' a la derecha por 1 bit
      const lsbSet = (v[15] & 1) !== 0
      for (let j = 15; j > 0; j--) {
        v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7)
      }
      v[0] >>= 1

      // Si el bit menos significativo de 'v' estaba activado, aplica la reducción polinomial
      if (lsbSet) {
        v[0] ^= 0b11100001 // Polinomio de reducción para POLYVAL (0xE1)
      }
    }
    return z
  }

  /**
   * Rellena un array de bytes para que su longitud sea un múltiplo de 16.
   * @private
   */
  private padToBlockSize(data: Uint8Array): Uint8Array {
    const len = data.length
    const remainder = len % 16
    if (remainder === 0) return data

    const padded = new Uint8Array(len + (16 - remainder))
    padded.set(data)
    return padded
  }

  /**
   * Crea un bloque de 16 bytes que contiene las longitudes en bits de AAD y texto.
   * Esta implementación utiliza manipulación pura de Uint8Array para un rendimiento óptimo.
   * @private
   */
  private createLengthBlock(aadLen: number, textLen: number): Uint8Array {
    const lenBlock = new Uint8Array(16)
    let n = aadLen * 8

    // Almacena la longitud de AAD en bits como un entero de 64 bits en formato little-endian
    for (let i = 0; i < 8; i++) {
      lenBlock[i] = n & 0xff
      // Usamos división en lugar de >> para manejar números mayores a 32 bits de forma segura
      n = Math.floor(n / 256)
    }

    n = textLen * 8
    // Almacena la longitud del texto en bits como un entero de 64 bits en formato little-endian
    for (let i = 8; i < 16; i++) {
      lenBlock[i] = n & 0xff
      n = Math.floor(n / 256)
    }

    return lenBlock
  }

  /**
   * Calcula el hash POLYVAL sobre los datos asociados y el texto cifrado.
   * @private
   */
  private hash(authKey: Uint8Array, associatedData: Uint8Array, text: Uint8Array): Uint8Array {
    let s = new Uint8Array(16)
    const aadPadded = this.padToBlockSize(associatedData)
    const textPadded = this.padToBlockSize(text)

    // Los datos se procesan en el orden: AAD, texto, bloque de longitudes
    const blocks = [aadPadded, textPadded, this.createLengthBlock(associatedData.length, text.length)]

    for (const data of blocks) {
      for (let i = 0; i < data.length; i += 16) {
        const block = data.subarray(i, i + 16)
        // s ^= block
        for (let j = 0; j < 16; j++) {
          s[j] ^= block[j]
        }
        // s = s * authKey
        s = this.polyvalMultiply(s, authKey)
      }
    }

    return s
  }

  /**
   * Cifra y autentica los datos usando AES-CWC.
   * @param plaintext El texto plano a cifrar.
   * @param nonce El nonce de 96 bits (12 bytes). No debe reutilizarse con la misma clave.
   * @param associatedData Datos adicionales que serán autenticados pero no cifrados.
   * @returns Un objeto con el `ciphertext` y la etiqueta de autenticación `tag`.
   */
  encrypt(plaintext: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): { ciphertext: Uint8Array; tag: Uint8Array } {
    if (nonce.length !== 12) {
      throw new Error("Tamaño de nonce inválido para CWC (debe ser 12 bytes)")
    }

    // --- FASE DE CIFRADO (CTR) ---
    // El contador se inicializa con el nonce y un contador de 32 bits empezando en 1.
    const initialCounter = new Uint8Array(16)
    initialCounter.set(nonce)
    initialCounter[15] = 1 // Inicia el contador en 1 para el cifrado de datos

    const ctr = new ModeOfOperationCTR(this.masterKey, new Counter(initialCounter))
    const ciphertext = ctr.encrypt(plaintext)

    // --- FASE DE AUTENTICACIÓN (MAC) ---
    // 1. Derivar la clave de hash H = E_K(0^128)
    const hashKey = this.aes.encrypt(new Uint8Array(16))

    // 2. Hashear los datos asociados (A) y el texto cifrado (C)
    const hashResult = this.hash(hashKey, associatedData, ciphertext)

    // 3. Cifrar el nonce para usarlo en el cálculo de la etiqueta.
    //    Se usa el nonce con el contador en 0.
    const nonceBlock = new Uint8Array(16)
    nonceBlock.set(nonce) // El contador por defecto (últimos 4 bytes) es 0

    const encryptedNonce = this.aes.encrypt(nonceBlock)

    // 4. La etiqueta es el resultado del hash XOR el nonce cifrado
    const tag = new Uint8Array(16)
    for (let i = 0; i < 16; i++) {
      tag[i] = hashResult[i] ^ encryptedNonce[i]
    }

    return { ciphertext, tag }
  }

  /**
   * Descifra y verifica la autenticidad de los datos.
   * @param ciphertext El texto cifrado.
   * @param tag La etiqueta de autenticación recibida.
   * @param nonce El mismo nonce usado en el cifrado.
   * @param associatedData Los mismos datos asociados usados en el cifrado.
   * @returns El texto plano si la autenticación es exitosa, o `null` si falla.
   */
  decrypt(ciphertext: Uint8Array, tag: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): Uint8Array | null {
    if (nonce.length !== 12) {
      throw new Error("Tamaño de nonce inválido para CWC (debe ser 12 bytes)")
    }
    if (tag.length !== 16) {
      return null // Etiqueta inválida, la verificación fallará
    }

    // --- FASE DE AUTENTICACIÓN (VERIFICACIÓN) ---
    // La verificación se realiza ANTES de intentar descifrar.
    // 1. Derivar la clave de hash H = E_K(0^128)
    const hashKey = this.aes.encrypt(new Uint8Array(16))

    // 2. Hashear A y C (el texto cifrado recibido)
    const hashResult = this.hash(hashKey, associatedData, ciphertext)

    // 3. Cifrar el nonce
    const nonceBlock = new Uint8Array(16)
    nonceBlock.set(nonce)
    const encryptedNonce = this.aes.encrypt(nonceBlock)

    // 4. Calcular la etiqueta esperada: Hash(A, C) XOR E_K(Nonce)
    const expectedTag = new Uint8Array(16)
    for (let i = 0; i < 16; i++) {
      expectedTag[i] = hashResult[i] ^ encryptedNonce[i]
    }

    // 5. Comparación en tiempo constante para evitar ataques de temporización
    let tagsMatch = 0
    for (let i = 0; i < 16; i++) {
      tagsMatch |= tag[i] ^ expectedTag[i]
    }

    if (tagsMatch !== 0) {
      return null // ¡Fallo de autenticación! Las etiquetas no coinciden.
    }

    // --- FASE DE DESCIFRADO (CTR) ---
    // Solo se ejecuta si la autenticación fue exitosa.
    const initialCounter = new Uint8Array(16)
    initialCounter.set(nonce)
    initialCounter[15] = 1 // Inicia el contador en 1, igual que en el cifrado

    const ctr = new ModeOfOperationCTR(this.masterKey, new Counter(initialCounter))
    const plaintext = ctr.decrypt(ciphertext)

    return plaintext
  }
}

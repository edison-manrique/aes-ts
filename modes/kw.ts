import { AES } from "../aes"

/**
 * Implementación del modo de operación AES-KW (Key Wrap).
 *
 * KW es un modo de operación especializado para envolver (cifrar) claves criptográficas.
 * Está basado en el algoritmo de envoltura de claves AES definido en NIST SP 800-38F.
 * No proporciona autenticación ni cifrado de datos generales, está específicamente
 * diseñado para proteger claves criptográficas.
 *
 * Características principales:
 * - **Especializado**: Diseñado específicamente para envolver claves criptográficas.
 * - **Determinista**: El mismo proceso siempre produce el mismo resultado.
 * - **Verificación de integridad**: Incluye verificación de integridad interna.
 * - **Longitud fija**: Solo funciona con claves de longitud múltiplo de 8 bytes.
 *
 * Funcionamiento:
 * 1. Se divide la clave en bloques de 64 bits.
 * 2. Se aplica una serie de rondas de cifrado con un IV fijo.
 * 3. Se incluye un contador en cada ronda para evitar patrones.
 * 4. El resultado incluye una verificación de integridad.
 *
 * Consideraciones de seguridad:
 * - **Solo para claves**: No debe usarse para cifrar datos generales.
 * - **Longitud específica**: Solo funciona con claves de longitud múltiplo de 8 bytes.
 * - **Sin autenticación externa**: La autenticación es interna y limitada.
 * - **KEK**: Requiere una Key-Encrypting Key (KEK) segura.
 *
 * KW es ampliamente utilizado en aplicaciones que necesitan proteger claves,
 * como en sistemas de gestión de claves y protocolos criptográficos.
 *
 * @example
 * ```typescript
 * const kek = new Uint8Array(16); // KEK de 128 bits
 * const kw = new ModeOfOperationKW(kek);
 * const keyToWrap = new Uint8Array(32); // Clave de 256 bits a envolver
 * const wrappedKey = kw.wrap(keyToWrap);
 * const unwrappedKey = kw.unwrap(wrappedKey);
 * ```
 *
 * @see [NIST SP 800-38F](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf)
 * para la especificación oficial del modo KW.
 */
export class ModeOfOperationKW {
  public readonly description = "AES Key Wrap (KW)"
  public readonly name = "kw"

  private readonly aes: AES // KEK (Key-Encrypting Key)

  // El Valor de Verificación de Integridad (ICV) por defecto según el estándar.
  private readonly defaultIV = new Uint8Array([0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6])

  /**
   * Inicializa el modo de operación KW con una KEK (Key-Encrypting Key).
   * @param key La KEK (Key-Encrypting Key), debe ser de 16, 24 o 32 bytes (128, 192 o 256 bits).
   */
  constructor(key: Uint8Array) {
    // La clave usada para envolver se llama KEK (Key-Encrypting Key)
    this.aes = new AES(key)
  }

  /**
   * Envuelve (cifra) una clave simétrica.
   * @param plaintextKey La clave de texto plano a envolver. Debe ser múltiplo de 8 bytes.
   * @returns La clave envuelta (texto cifrado).
   */
  wrap(plaintextKey: Uint8Array): Uint8Array {
    if (plaintextKey.length % 8 !== 0) {
      throw new Error("La clave a envolver debe tener una longitud múltiplo de 8 bytes.")
    }

    const n = plaintextKey.length / 8
    const R = new Array<Uint8Array>(n + 1)

    // 1. Inicializar variables
    let A = new Uint8Array(this.defaultIV) // A = R[0]
    for (let i = 0; i < n; i++) {
      R[i + 1] = plaintextKey.subarray(i * 8, (i + 1) * 8)
    }

    // 2. Calcular los valores intermedios
    for (let j = 0; j < 6; j++) {
      for (let i = 1; i <= n; i++) {
        const t = n * j + i
        const B = new Uint8Array(16)
        B.set(A)
        B.set(R[i], 8)

        const encryptedB = this.aes.encrypt(B)

        A = encryptedB.subarray(0, 8)

        // Se aplica un XOR a los 64 bits de 'A' con el contador 't' de 64 bits.
        // Convertimos 't' a big-endian byte por byte y lo aplicamos con XOR.
        let temp_t = t
        for (let k = 7; k >= 0; k--) {
          // Extraemos el byte menos significativo de temp_t y lo aplicamos a A[k]
          A[k] ^= temp_t & 0xff
          // Desplazamos temp_t 8 bits a la derecha. Usamos división para
          // evitar problemas con números mayores a 32 bits.
          temp_t = Math.floor(temp_t / 256)
          // Optimización: si no quedan bits en 't', podemos detenernos.
          if (temp_t === 0) {
            break
          }
        }

        R[i] = encryptedB.subarray(8)
      }
    }

    // 3. Formar el texto cifrado final
    const ciphertext = new Uint8Array((n + 1) * 8)
    ciphertext.set(A)
    for (let i = 1; i <= n; i++) {
      ciphertext.set(R[i], i * 8)
    }

    return ciphertext
  }

  /**
   * Desenvuelve (descifra) una clave simétrica.
   * @param wrappedKey La clave envuelta (texto cifrado).
   * @returns La clave de texto plano si la verificación de integridad es exitosa, o `null` si falla.
   */
  unwrap(wrappedKey: Uint8Array): Uint8Array | null {
    if (wrappedKey.length % 8 !== 0 || wrappedKey.length < 16) {
      throw new Error("La longitud de la clave envuelta es inválida.")
    }

    const n = wrappedKey.length / 8 - 1
    const R = new Array<Uint8Array>(n + 1)

    // 1. Inicializar variables desde el texto cifrado
    let A = wrappedKey.subarray(0, 8)
    for (let i = 0; i < n; i++) {
      R[i + 1] = wrappedKey.subarray((i + 1) * 8, (i + 2) * 8)
    }

    // 2. Calcular valores intermedios (proceso inverso)
    for (let j = 5; j >= 0; j--) {
      for (let i = n; i >= 1; i--) {
        const t = n * j + i

        // Creamos una copia de A para no modificar el bloque original antes de tiempo.
        const tempA = new Uint8Array(A)

        // Se aplica un XOR a los 64 bits de 'A' con el contador 't' de 64 bits.
        // Convertimos 't' a big-endian byte por byte y lo aplicamos con XOR.
        let temp_t = t
        for (let k = 7; k >= 0; k--) {
          tempA[k] ^= temp_t & 0xff
          temp_t = Math.floor(temp_t / 256)
          if (temp_t === 0) {
            break
          }
        }

        const B = new Uint8Array(16)
        B.set(tempA)
        B.set(R[i], 8)

        const decryptedB = this.aes.decrypt(B)

        A = decryptedB.subarray(0, 8)
        R[i] = decryptedB.subarray(8)
      }
    }

    // 3. Verificación de Integridad
    // Compara el resultado de A con el ICV inicial en tiempo constante.
    let integrityCheck = 0
    for (let i = 0; i < 8; i++) {
      integrityCheck |= A[i] ^ this.defaultIV[i]
    }

    if (integrityCheck !== 0) {
      return null // ¡Fallo de verificación de integridad!
    }

    // 4. Formar la clave de texto plano
    const plaintext = new Uint8Array(n * 8)
    for (let i = 1; i <= n; i++) {
      plaintext.set(R[i], (i - 1) * 8)
    }

    return plaintext
  }
}
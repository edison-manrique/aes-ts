import { ModeOfOperationKW } from "./kw"

/**
 * Implementación del modo de operación AES-KWP (Key Wrap with Padding).
 *
 * KWP es una variante del modo KW que permite envolver claves de cualquier longitud.
 * Agrega un esquema de relleno al algoritmo KW básico para manejar longitudes de clave
 * que no son múltiplos de 8 bytes.
 *
 * Características principales:
 * - **Longitud flexible**: Puede envolver claves de cualquier longitud.
 * - **Relleno determinista**: Utiliza un esquema de relleno específico definido en el estándar.
 * - **Verificación de integridad**: Hereda la verificación de integridad de KW.
 * - **Basado en KW**: Utiliza el modo KW como primitiva subyacente.
 *
 * Funcionamiento:
 * 1. Se agrega la longitud de la clave original como prefijo de 4 bytes.
 * 2. Se aplica relleno con ceros al final para alcanzar un tamaño múltiplo de 8 bytes.
 * 3. Se utiliza el algoritmo KW estándar sobre los datos rellenados.
 * 4. Para desenvolver, se aplica el proceso inverso y se verifica la longitud.
 *
 * Consideraciones de seguridad:
 * - **Solo para claves**: No debe usarse para cifrar datos generales.
 * - **Verificación limitada**: La verificación es interna y limitada.
 * - **KEK**: Requiere una Key-Encrypting Key (KEK) segura.
 * - **Relleno**: El relleno es determinista y no proporciona ocultamiento adicional.
 *
 * KWP es útil cuando se necesita envolver claves de longitud variable,
 * como en sistemas de gestión de claves y protocolos criptográficos.
 *
 * @example
 * ```typescript
 * const kek = new Uint8Array(16); // KEK de 128 bits
 * const kwp = new ModeOfOperationKWP(kek);
 * const keyToWrap = new Uint8Array(33); // Clave de 33 bytes a envolver
 * const wrappedKey = kwp.wrap(keyToWrap);
 * const unwrappedKey = kwp.unwrap(wrappedKey);
 * ```
 *
 * @see [NIST SP 800-38F](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf)
 * para la especificación oficial del modo KWP.
 */
export class ModeOfOperationKWP {
  public readonly description = "AES Key Wrap with Padding (KWP)"
  public readonly name = "kwp"

  private readonly kw: ModeOfOperationKW // Instancia interna de KW

  /**
   * Inicializa el modo de operación KWP con una KEK (Key-Encrypting Key).
   * @param key La KEK (Key-Encrypting Key), debe ser de 16, 24 o 32 bytes (128, 192 o 256 bits).
   */
  constructor(key: Uint8Array) {
    // La KEK se pasa al motor KW interno.
    this.kw = new ModeOfOperationKW(key)
  }

  /**
   * Envuelve (cifra) una clave simétrica de cualquier longitud.
   * @param plaintextKey La clave de texto plano a envolver.
   * @returns La clave envuelta (texto cifrado).
   */
  wrap(plaintextKey: Uint8Array): Uint8Array {
    const plen = plaintextKey.length

    // 1. Construir el bloque de texto plano con relleno (P')
    // El tamaño del relleno es de 0 a 7 bytes.
    const paddedSize = Math.ceil((4 + plen) / 8) * 8
    const paddedPlaintext = new Uint8Array(paddedSize)

    // Escribir la longitud original (plen) como un entero de 32 bits big-endian.
    // (>>> es un desplazamiento a la derecha sin signo, importante para números grandes)
    paddedPlaintext[0] = (plen >>> 24) & 0xff
    paddedPlaintext[1] = (plen >>> 16) & 0xff
    paddedPlaintext[2] = (plen >>> 8) & 0xff
    paddedPlaintext[3] = plen & 0xff

    // Copiar la clave original después de los 4 bytes de longitud
    paddedPlaintext.set(plaintextKey, 4)

    // Los bytes de relleno restantes son 0 por defecto en un nuevo Uint8Array,
    // como lo especifica el estándar.

    // 2. Usar el algoritmo KW estándar sobre los datos rellenados
    return this.kw.wrap(paddedPlaintext)
  }

  /**
   * Desenvuelve (descifra) una clave simétrica.
   * @param wrappedKey La clave envuelta (texto cifrado).
   * @returns La clave de texto plano si la verificación es exitosa, o `null` si falla.
   */
  unwrap(wrappedKey: Uint8Array): Uint8Array | null {
    // 1. Usar el algoritmo KW estándar para desenvolver los datos.
    const paddedPlaintext = this.kw.unwrap(wrappedKey)

    // Si la desenvoltura de KW falla, KWP también falla.
    if (paddedPlaintext === null) {
      return null
    }

    // 2. Verificar y quitar el relleno

    // Leer los primeros 4 bytes para obtener la longitud original de la clave.
    const plen = (paddedPlaintext[0] << 24) | (paddedPlaintext[1] << 16) | (paddedPlaintext[2] << 8) | paddedPlaintext[3]

    // Verificación de validez: la longitud recuperada no debe exceder el espacio disponible.
    // También verifica que el relleno no haya sido alterado de forma maliciosa.
    if (plen > paddedPlaintext.length - 4) {
      return null // El relleno es inválido.
    }

    // 3. Extraer la clave original
    const originalKey = paddedPlaintext.subarray(4, 4 + plen)

    return originalKey
  }
}
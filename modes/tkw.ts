import { ModeOfOperationKW } from "./kw"

/**
 * Implementación del modo de operación AES-TKW (Tweakable Key Wrap).
 *
 * TKW es una variante del modo KW que permite vincular (bind) una clave envuelta
 * a metadatos públicos llamados "tweak". Esto proporciona una forma de asegurar
 * que una clave solo pueda desenvolverse cuando se proporciona el tweak correcto.
 *
 * Características principales:
 * - **Tweakable**: Permite vincular una clave a metadatos específicos.
 * - **Verificación de tweak**: El tweak se verifica durante el desenvolvimiento.
 * - **Basado en KW**: Utiliza el modo KW como primitiva subyacente.
 * - **Seguridad adicional**: Proporciona una capa adicional de verificación.
 *
 * Proceso:
 * 1. Se rellena el tweak a un múltiplo de 8 bytes.
 * 2. Se aplica el esquema de relleno de KWP a la clave.
 * 3. Se concatenan el tweak relleno y la clave rellenada.
 * 4. Se utiliza el algoritmo KW estándar sobre los datos concatenados.
 * 5. Para desenvolver, se verifica que el tweak coincida con el proporcionado.
 *
 * @example
 * ```typescript
 * const kek = new Uint8Array(16); // KEK de 128 bits
 * const tkw = new ModeOfOperationTKW(kek);
 * const keyToWrap = new Uint8Array(32); // Clave de 256 bits a envolver
 * const tweak = new TextEncoder().encode("metadatos");
 * const wrappedKey = tkw.wrap(keyToWrap, tweak);
 * const unwrappedKey = tkw.unwrap(wrappedKey, tweak);
 * ```
 *
 * @see [NIST SP 800-38F](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf)
 * para la especificación oficial del modo TKW.
 */
export class ModeOfOperationTKW {
  public readonly description = "AES Tweakable Key Wrap (TKW)"
  public readonly name = "tkw"

  private readonly kw: ModeOfOperationKW // Motor KW base

  /**
   * Inicializa el modo de operación TKW con una KEK (Key-Encrypting Key).
   * @param key La KEK (Key-Encrypting Key), debe ser de 16, 24 o 32 bytes (128, 192 o 256 bits).
   */
  constructor(key: Uint8Array) {
    // La KEK se pasa al motor KW base.
    this.kw = new ModeOfOperationKW(key)
  }

  /**
   * Envuelve (cifra) una clave simétrica, vinculándola a un tweak.
   * @param plaintextKey La clave de texto plano a envolver.
   * @param tweak Los metadatos públicos (tweak).
   * @returns La clave envuelta (texto cifrado).
   */
  wrap(plaintextKey: Uint8Array, tweak: Uint8Array): Uint8Array {
    // 1. Rellenar el tweak a un múltiplo de 8 bytes.
    const paddedTweakSize = Math.ceil(tweak.length / 8) * 8
    const paddedTweak = new Uint8Array(paddedTweakSize)
    paddedTweak.set(tweak)

    // 2. Rellenar la clave de texto plano usando la lógica de KWP.
    const plen = plaintextKey.length
    const paddedPlaintextSize = Math.ceil((4 + plen) / 8) * 8
    const paddedPlaintext = new Uint8Array(paddedPlaintextSize)
    paddedPlaintext[0] = (plen >>> 24) & 0xff
    paddedPlaintext[1] = (plen >>> 16) & 0xff
    paddedPlaintext[2] = (plen >>> 8) & 0xff
    paddedPlaintext[3] = plen & 0xff
    paddedPlaintext.set(plaintextKey, 4)

    // 3. Concatenar los bloques rellenados.
    const dataToWrap = new Uint8Array(paddedTweak.length + paddedPlaintext.length)
    dataToWrap.set(paddedTweak)
    dataToWrap.set(paddedPlaintext, paddedTweak.length)

    // 4. Usar el algoritmo KW estándar sobre los datos concatenados.
    return this.kw.wrap(dataToWrap)
  }

  /**
   * Desenvuelve (descifra) una clave simétrica, verificando el tweak.
   * @param wrappedKey La clave envuelta (texto cifrado).
   * @param tweak El mismo tweak usado durante la envoltura.
   * @returns La clave de texto plano si la verificación es exitosa, o `null` si falla.
   */
  unwrap(wrappedKey: Uint8Array, tweak: Uint8Array): Uint8Array | null {
    // 1. Usar el algoritmo KW estándar para desenvolver los datos.
    const unwrappedData = this.kw.unwrap(wrappedKey)
    if (unwrappedData === null) {
      return null // Falla la integridad base de KW.
    }

    // 2. Rellenar el tweak proporcionado para la comparación.
    const paddedTweakSize = Math.ceil(tweak.length / 8) * 8
    if (unwrappedData.length < paddedTweakSize) {
      return null // El dato desenvuelto es demasiado corto para contener el tweak.
    }
    const paddedTweak = new Uint8Array(paddedTweakSize)
    paddedTweak.set(tweak)

    // 3. Extraer el tweak desenvuelto y el bloque de clave rellenado.
    const unwrappedTweak = unwrappedData.subarray(0, paddedTweakSize)
    const paddedPlaintext = unwrappedData.subarray(paddedTweakSize)

    // 4. Verificar que el tweak coincida (en tiempo constante).
    let tweaksMatch = 0
    for (let i = 0; i < paddedTweakSize; i++) {
      tweaksMatch |= unwrappedTweak[i] ^ paddedTweak[i]
    }
    if (tweaksMatch !== 0) {
      return null // ¡El tweak no coincide! Falla la verificación.
    }

    // 5. Si el tweak coincide, procesar el resto como en KWP.
    if (paddedPlaintext.length < 4) return null // Debe haber al menos 4 bytes para la longitud.

    const plen = (paddedPlaintext[0] << 24) | (paddedPlaintext[1] << 16) | (paddedPlaintext[2] << 8) | paddedPlaintext[3]

    if (plen > paddedPlaintext.length - 4) {
      return null // Relleno inválido.
    }

    return paddedPlaintext.subarray(4, 4 + plen)
  }
}
import { ModeOfOperationKW } from "./kw"

// --- AES-TKW (Tweakable Key Wrap - NIST SP 800-38F) ---
export class ModeOfOperationTKW {
  public readonly description = "AES Tweakable Key Wrap (TKW)"
  public readonly name = "tkw"

  private readonly kw: ModeOfOperationKW // Motor KW base

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

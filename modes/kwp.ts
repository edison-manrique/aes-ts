import { ModeOfOperationKW } from "./kw"

// --- AES-KWP (Key Wrap with Padding - NIST SP 800-38F) ---
export class ModeOfOperationKWP {
  public readonly description = "AES Key Wrap with Padding (KWP)"
  public readonly name = "kwp"

  private readonly kw: ModeOfOperationKW // Instancia interna de KW

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
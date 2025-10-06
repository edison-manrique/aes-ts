/**
 * Añade relleno PKCS7 a los datos.
 * @param data - El Uint8Array al que se le añadirá el relleno.
 * @param blockSize - Opcional. El tamaño del bloque al que se debe rellenar. Por defecto es 16.
 * @returns Un nuevo Uint8Array con el relleno añadido.
 */
export function pkcs7pad(data: Uint8Array, blockSize: number = 16): Uint8Array {
  // Calcula la cantidad de bytes que se deben agregar para el relleno.
  const paddingValue = blockSize - (data.length % blockSize)

  // Si el texto ya es un múltiplo del tamaño del bloque, se agrega un bloque completo de relleno.
  // Esto es parte del estándar PKCS#7.
  const bytesToAdd = paddingValue === 0 ? blockSize : paddingValue

  const result = new Uint8Array(data.length + bytesToAdd)
  result.set(data)
  result.fill(bytesToAdd, data.length)
  return result
}

/**
 * Elimina el relleno PKCS7 de los datos.
 * @param data - El Uint8Array del que se eliminará el relleno.
 * @returns Un nuevo Uint8Array sin el relleno.
 * @throws Si el relleno es inválido.
 */
export function pkcs7strip(data: Uint8Array, blockSize: number = 16): Uint8Array {
  if (data.length === 0) {
    throw new Error("PKCS#7: El array de entrada no puede estar vacío.")
  }

  const paddingValue = data[data.length - 1]

  // El valor de relleno debe ser entre 1 y 16 (o el tamaño del bloque máximo).
  // Y el array de entrada debe ser de al menos el tamaño del relleno.
  if (paddingValue === 0 || paddingValue > blockSize || data.length < paddingValue) {
    throw new Error("PKCS#7: byte de relleno fuera de rango o longitud inválida.")
  }

  const length = data.length - paddingValue

  // Verifica que todos los bytes de relleno sean iguales al valor de relleno.
  for (let i = 0; i < paddingValue; i++) {
    if (data[length + i] !== paddingValue) {
      throw new Error("PKCS#7: byte de relleno inválido.")
    }
  }

  return data.slice(0, length)
}

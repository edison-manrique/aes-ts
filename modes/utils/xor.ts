/**
 * Realiza una operación XOR entre dos arrays de bytes.
 * @private
 */
export function xor(a: Uint8Array, b: Uint8Array): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(a.length)
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i]
  }
  return result
}

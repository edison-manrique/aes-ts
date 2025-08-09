import { AES } from "../aes"

// --- CFB (Cipher Feedback) ---
export class ModeOfOperationCFB {
  public readonly description = "Cipher Feedback"
  public readonly name = "cfb"
  private readonly aes: AES
  private readonly segmentSize: number
  private shiftRegister: Uint8Array

  constructor(key: Uint8Array, iv?: Uint8Array, segmentSize: number = 1) {
    this.aes = new AES(key)
    this.segmentSize = segmentSize

    if (iv && iv.length !== 16) {
      throw new Error("Tamaño de vector de inicialización inválido (debe ser 16 bytes)")
    }
    this.shiftRegister = iv ? new Uint8Array(iv) : new Uint8Array(16)
  }

  encrypt(plaintext: Uint8Array): Uint8Array {
    if (plaintext.length % this.segmentSize !== 0) {
      throw new Error(`Tamaño de texto plano inválido (debe ser múltiplo de segmentSize: ${this.segmentSize} bytes)`)
    }

    const ciphertext = new Uint8Array(plaintext)

    for (let i = 0; i < ciphertext.length; i += this.segmentSize) {
      const xorSegment = this.aes.encrypt(this.shiftRegister)

      // XOR del texto plano con el segmento cifrado para obtener el texto cifrado
      for (let j = 0; j < this.segmentSize; j++) {
        ciphertext[i + j] ^= xorSegment[j]
      }

      // Actualiza el registro de desplazamiento:
      // 1. Desplaza el registro a la izquierda
      this.shiftRegister.set(this.shiftRegister.subarray(this.segmentSize))
      // 2. Coloca el nuevo texto cifrado al final del registro
      this.shiftRegister.set(ciphertext.subarray(i, i + this.segmentSize), 16 - this.segmentSize)
    }

    return ciphertext
  }

  decrypt(ciphertext: Uint8Array): Uint8Array {
    if (ciphertext.length % this.segmentSize !== 0) {
      throw new Error(`Tamaño de texto cifrado inválido (debe ser múltiplo de segmentSize: ${this.segmentSize} bytes)`)
    }

    const plaintext = new Uint8Array(ciphertext)

    for (let i = 0; i < plaintext.length; i += this.segmentSize) {
      const xorSegment = this.aes.encrypt(this.shiftRegister)

      // Guarda el segmento de texto cifrado actual ANTES de la operación XOR
      const currentCiphertextSegment = ciphertext.subarray(i, i + this.segmentSize)

      // XOR del texto cifrado con el segmento cifrado para obtener el texto plano
      for (let j = 0; j < this.segmentSize; j++) {
        plaintext[i + j] ^= xorSegment[j]
      }

      // Actualiza el registro de desplazamiento:
      // 1. Desplaza el registro a la izquierda
      this.shiftRegister.set(this.shiftRegister.subarray(this.segmentSize))
      // 2. Coloca el texto cifrado original al final del registro
      this.shiftRegister.set(currentCiphertextSegment, 16 - this.segmentSize)
    }

    return plaintext
  }
}

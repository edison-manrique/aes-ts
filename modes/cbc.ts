import { AES } from "../aes"

// --- CBC (Cipher Block Chaining) ---
export class ModeOfOperationCBC {
  public readonly description = "Cipher Block Chaining"
  public readonly name = "cbc"
  private lastCipherblock: Uint8Array
  private readonly aes: AES

  constructor(key: Uint8Array, iv?: Uint8Array) {
    if (iv && iv.length !== 16) {
      throw new Error("Tamaño de vector de inicialización inválido (debe ser 16 bytes)")
    }
    this.lastCipherblock = iv ? new Uint8Array(iv) : new Uint8Array(16)
    this.aes = new AES(key)
  }

  encrypt(plaintext: Uint8Array): Uint8Array {
    if (plaintext.length % 16 !== 0) {
      throw new Error("Tamaño de texto plano inválido (debe ser múltiplo de 16 bytes)")
    }

    const ciphertext = new Uint8Array(plaintext.length)
    for (let i = 0; i < plaintext.length; i += 16) {
      const block = plaintext.subarray(i, i + 16)
      for (let j = 0; j < 16; j++) {
        block[j] ^= this.lastCipherblock[j]
      }
      this.lastCipherblock = this.aes.encrypt(block)
      ciphertext.set(this.lastCipherblock, i)
    }
    return ciphertext
  }

  decrypt(ciphertext: Uint8Array): Uint8Array {
    if (ciphertext.length % 16 !== 0) {
      throw new Error("Tamaño de texto cifrado inválido (debe ser múltiplo de 16 bytes)")
    }

    const plaintext = new Uint8Array(ciphertext.length)
    for (let i = 0; i < ciphertext.length; i += 16) {
      const block = ciphertext.subarray(i, i + 16)
      const decryptedBlock = this.aes.decrypt(block)
      for (let j = 0; j < 16; j++) {
        plaintext[i + j] = decryptedBlock[j] ^ this.lastCipherblock[j]
      }
      this.lastCipherblock = block
    }
    return plaintext
  }
}

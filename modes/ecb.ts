import { AES } from "../aes"

// --- ECB (Electronic Codebook) ---
export class ModeOfOperationECB {
  public readonly description = "Electronic Codebook"
  public readonly name = "ecb"
  private readonly aes: AES

  constructor(key: Uint8Array) {
    this.aes = new AES(key)
  }

  encrypt(plaintext: Uint8Array): Uint8Array {
    if (plaintext.length % 16 !== 0) {
      throw new Error("Tamaño de texto plano inválido (debe ser múltiplo de 16 bytes)")
    }

    const ciphertext = new Uint8Array(plaintext.length)
    for (let i = 0; i < plaintext.length; i += 16) {
      const block = plaintext.subarray(i, i + 16)
      const encryptedBlock = this.aes.encrypt(block)
      ciphertext.set(encryptedBlock, i)
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
      plaintext.set(decryptedBlock, i)
    }
    return plaintext
  }
}
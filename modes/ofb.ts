import { AES } from "../aes"

// --- OFB (Output Feedback) ---
export class ModeOfOperationOFB {
  public readonly description = "Output Feedback"
  public readonly name = "ofb"
  private readonly aes: AES
  private lastPrecipher: Uint8Array
  private lastPrecipherIndex: number

  constructor(key: Uint8Array, iv?: Uint8Array) {
    this.aes = new AES(key)
    this.lastPrecipherIndex = 16

    if (iv && iv.length !== 16) {
      throw new Error("Tamaño de vector de inicialización inválido (debe ser 16 bytes)")
    }
    this.lastPrecipher = iv ? iv : new Uint8Array(16)
  }

  encrypt(plaintext: Uint8Array): Uint8Array {
    const encrypted = new Uint8Array(plaintext)

    for (let i = 0; i < encrypted.length; i++) {
      if (this.lastPrecipherIndex === 16) {
        this.lastPrecipher = this.aes.encrypt(this.lastPrecipher)
        this.lastPrecipherIndex = 0
      }
      encrypted[i] ^= this.lastPrecipher[this.lastPrecipherIndex++]
    }

    return encrypted
  }

  // En OFB, la desencriptación es simétrica a la encriptación
  decrypt = this.encrypt
}
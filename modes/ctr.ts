import { AES } from "../aes"

// --- CTR (Counter) ---
export class Counter {
  private _counter: Uint8Array

  constructor(initialValue: number | Uint8Array = 1) {
    if (typeof initialValue === "number") {
      if (!Number.isSafeInteger(initialValue)) {
        throw new Error("Valor de contador entero fuera de rango seguro")
      }
      this._counter = new Uint8Array(16)
      this.setValue(initialValue)
    } else {
      if (initialValue.length !== 16) {
        throw new Error("Tamaño de bytes de contador inválido (debe ser 16 bytes)")
      }
      this._counter = new Uint8Array(initialValue)
    }
  }

  setValue(value: number): void {
    if (!Number.isSafeInteger(value)) {
      throw new Error("Valor de contador inválido (debe ser un entero seguro)")
    }
    for (let i = 15; i >= 0; --i) {
      this._counter[i] = value % 256
      value = Math.floor(value / 256)
    }
  }

  increment(): void {
    for (let i = 15; i >= 0; i--) {
      if (this._counter[i] === 255) {
        this._counter[i] = 0
      } else {
        this._counter[i]++
        break
      }
    }
  }

  get counterBytes(): Uint8Array {
    return this._counter
  }
}

export class ModeOfOperationCTR {
  public readonly description = "Counter"
  public readonly name = "ctr"
  private readonly aes: AES
  private readonly counter: Counter
  private remainingCounter: Uint8Array | null = null
  private remainingCounterIndex = 16

  constructor(key: Uint8Array, counter?: Counter | number | Uint8Array) {
    this.aes = new AES(key)
    if (counter instanceof Counter) {
      this.counter = counter
    } else {
      this.counter = new Counter(counter)
    }
  }

  encrypt(plaintext: Uint8Array): Uint8Array {
    const encrypted = new Uint8Array(plaintext)
    for (let i = 0; i < encrypted.length; i++) {
      if (this.remainingCounterIndex === 16) {
        this.remainingCounter = this.aes.encrypt(this.counter.counterBytes)
        this.remainingCounterIndex = 0
        this.counter.increment()
      }
      encrypted[i] ^= this.remainingCounter![this.remainingCounterIndex++]
    }
    return encrypted
  }

  decrypt = this.encrypt
}

import { NUMBER_OF_ROUNDS, RCON, S, SI, T1, T2, T3, T4, T5, T6, T7, T8, U1, U2, U3, U4 } from "./constants"

export class AES {
  private readonly key: Uint8Array
  private readonly _Ke: number[][] = []
  private readonly _Kd: number[][] = []

  constructor(key: Uint8Array) {
    this.key = new Uint8Array(key)
    this.prepare()
  }

  private prepare(): void {
    const rounds = NUMBER_OF_ROUNDS[this.key.length]
    if (rounds == null) {
      throw new Error("Tamaño de clave inválido (debe ser 16, 24 o 32 bytes)")
    }

    for (let i = 0; i <= rounds; i++) {
      this._Ke.push([0, 0, 0, 0])
      this._Kd.push([0, 0, 0, 0])
    }

    const roundKeyCount = (rounds + 1) * 4
    const KC = this.key.length / 4
    const tk = this.convertToInt32(this.key)

    for (let i = 0; i < KC; i++) {
      const index = i >> 2
      this._Ke[index][i % 4] = tk[i]
      this._Kd[rounds - index][i % 4] = tk[i]
    }

    let rconPointer = 0
    let t = KC
    while (t < roundKeyCount) {
      let tt = tk[KC - 1]
      tk[0] ^= (S[(tt >> 16) & 0xff] << 24) ^ (S[(tt >> 8) & 0xff] << 16) ^ (S[tt & 0xff] << 8) ^ S[(tt >> 24) & 0xff] ^ (RCON[rconPointer++] << 24)

      if (KC !== 8) {
        for (let i = 1; i < KC; i++) {
          tk[i] ^= tk[i - 1]
        }
      } else {
        for (let i = 1; i < KC / 2; i++) {
          tk[i] ^= tk[i - 1]
        }
        tt = tk[KC / 2 - 1]
        tk[KC / 2] ^= S[tt & 0xff] ^ (S[(tt >> 8) & 0xff] << 8) ^ (S[(tt >> 16) & 0xff] << 16) ^ (S[(tt >> 24) & 0xff] << 24)
        for (let i = KC / 2 + 1; i < KC; i++) {
          tk[i] ^= tk[i - 1]
        }
      }

      let i = 0
      while (i < KC && t < roundKeyCount) {
        const r = t >> 2
        const c = t % 4
        this._Ke[r][c] = tk[i]
        this._Kd[rounds - r][c] = tk[i++]
        t++
      }
    }

    for (let r = 1; r < rounds; r++) {
      for (let c = 0; c < 4; c++) {
        const tt = this._Kd[r][c]
        this._Kd[r][c] = U1[(tt >> 24) & 0xff] ^ U2[(tt >> 16) & 0xff] ^ U3[(tt >> 8) & 0xff] ^ U4[tt & 0xff]
      }
    }
  }

  private convertToInt32(bytes: Uint8Array): number[] {
    const result: number[] = []
    for (let i = 0; i < bytes.length; i += 4) {
      result.push((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3])
    }
    return result
  }

  public encrypt(plaintext: Uint8Array): Uint8Array<ArrayBuffer> {
    if (plaintext.length !== 16) {
      throw new Error("Tamaño de texto plano inválido (debe ser 16 bytes)")
    }

    const rounds = this._Ke.length - 1
    let t = this.convertToInt32(plaintext)

    for (let i = 0; i < 4; i++) {
      t[i] ^= this._Ke[0][i]
    }

    for (let r = 1; r < rounds; r++) {
      const a = [0, 0, 0, 0]
      for (let i = 0; i < 4; i++) {
        a[i] = T1[(t[i] >> 24) & 0xff] ^ T2[(t[(i + 1) % 4] >> 16) & 0xff] ^ T3[(t[(i + 2) % 4] >> 8) & 0xff] ^ T4[t[(i + 3) % 4] & 0xff] ^ this._Ke[r][i]
      }
      t = a
    }

    const result = new Uint8Array(16)
    for (let i = 0; i < 4; i++) {
      const tt = this._Ke[rounds][i]
      result[4 * i] = (S[(t[i] >> 24) & 0xff] ^ (tt >> 24)) & 0xff
      result[4 * i + 1] = (S[(t[(i + 1) % 4] >> 16) & 0xff] ^ (tt >> 16)) & 0xff
      result[4 * i + 2] = (S[(t[(i + 2) % 4] >> 8) & 0xff] ^ (tt >> 8)) & 0xff
      result[4 * i + 3] = (S[t[(i + 3) % 4] & 0xff] ^ tt) & 0xff
    }
    return result
  }

  public decrypt(ciphertext: Uint8Array): Uint8Array<ArrayBuffer> {
    if (ciphertext.length !== 16) {
      throw new Error("Tamaño de texto cifrado inválido (debe ser 16 bytes)")
    }

    const rounds = this._Kd.length - 1
    let t = this.convertToInt32(ciphertext)

    for (let i = 0; i < 4; i++) {
      t[i] ^= this._Kd[0][i]
    }

    for (let r = 1; r < rounds; r++) {
      const a = [0, 0, 0, 0]
      for (let i = 0; i < 4; i++) {
        a[i] = T5[(t[i] >> 24) & 0xff] ^ T6[(t[(i + 3) % 4] >> 16) & 0xff] ^ T7[(t[(i + 2) % 4] >> 8) & 0xff] ^ T8[t[(i + 1) % 4] & 0xff] ^ this._Kd[r][i]
      }
      t = a
    }

    const result = new Uint8Array(16)
    for (let i = 0; i < 4; i++) {
      const tt = this._Kd[rounds][i]
      result[4 * i] = (SI[(t[i] >> 24) & 0xff] ^ (tt >> 24)) & 0xff
      result[4 * i + 1] = (SI[(t[(i + 3) % 4] >> 16) & 0xff] ^ (tt >> 16)) & 0xff
      result[4 * i + 2] = (SI[(t[(i + 2) % 4] >> 8) & 0xff] ^ (tt >> 8)) & 0xff
      result[4 * i + 3] = (SI[t[(i + 1) % 4] & 0xff] ^ tt) & 0xff
    }
    return result
  }
}

import { AES } from "../aes"

/**
 * Implementación de AES-FPE en modo FF1 (Format-Preserving Encryption), conforme a NIST SP 800-38G.
 *
 * FPE (Format-Preserving Encryption) es una técnica criptográfica que permite cifrar datos
 * manteniendo el formato de los mismos. FF1 es uno de los modos estándar para FPE.
 *
 * Características principales:
 * - **Preservación de formato**: El texto cifrado tiene el mismo formato que el texto plano.
 * - **Alfabeto personalizable**: Se puede especificar cualquier alfabeto para los datos a cifrar.
 * - **Seguridad**: Basado en AES, proporciona seguridad criptográfica robusta.
 * - **Aplicaciones típicas**: Números de tarjetas de crédito, números de seguridad social, etc.
 *
 * Proceso:
 * 1. Se divide el texto en dos mitades.
 * 2. Se utiliza una cadena de PRF (Pseudo-Random Function) para generar valores de ronda.
 * 3. Se aplican múltiples rondas de cifrado con feedforward.
 * 4. Se combinan los resultados para obtener el texto cifrado final.
 *
 * @example
 * ```typescript
 * const key = new Uint8Array(32); // Clave de 256 bits
 * const alphabet = "0123456789"; // Solo dígitos
 * const ff1 = new ModeOfOperationFPE_FF1(key, alphabet);
 * const plaintext = "1234567890123456";
 * 
 * const ciphertext = ff1.encrypt(plaintext, "tweak");
 * const decrypted = ff1.decrypt(ciphertext, "tweak");
 * ```
 *
 * @see [NIST SP 800-38G](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf) para la especificación oficial.
 */
export class ModeOfOperationFPE_FF1 {
  public readonly description = "Format-Preserving Encryption (FF1)"
  public readonly name = "fpe-ff1"

  private readonly aes: AES
  private readonly radix: number
  private readonly minLen: number
  private readonly maxLen: number

  private readonly charToNum: Map<string, number>
  private readonly numToChar: string[]

  /**
   * Inicializa el modo de operación FPE-FF1 con una clave maestra y un alfabeto.
   * @param key La clave maestra AES.
   * @param alphabet El alfabeto de caracteres permitidos en el texto plano y cifrado.
   */
  constructor(key: Uint8Array, alphabet: string) {
    this.aes = new AES(key)
    this.radix = alphabet.length

    if (this.radix < 2 || this.radix > 2 ** 16) {
      throw new Error("El tamaño del alfabeto (radix) debe estar entre 2 y 65536.")
    }

    const minLengthFromRadix = Math.ceil(Math.log(1000000) / Math.log(this.radix))
    this.minLen = Math.max(2, minLengthFromRadix)
    this.maxLen = 2 ** 32

    this.charToNum = new Map(Array.from(alphabet).map((char, i) => [char, i]))
    this.numToChar = Array.from(alphabet)
  }

  // --- Funciones de Conversión de Tipos (Sin cambios, ya son compatibles) ---
  private _stringToNumerals(input: string): number[] {
    const numerals = new Array(input.length)
    for (let i = 0; i < input.length; i++) {
      const num = this.charToNum.get(input[i])
      if (num === undefined) throw new Error(`El carácter '${input[i]}' no se encuentra en el alfabeto.`)
      numerals[i] = num
    }
    return numerals
  }

  private _numeralsToString(input: number[]): string {
    let str = ""
    for (let i = 0; i < input.length; i++) {
      str += this.numToChar[input[i]]
    }
    return str
  }

  private _numeralsToBigInt(numerals: number[]): bigint {
    let num = 0n
    const bigRadix = BigInt(this.radix)
    for (const n of numerals) {
      num = num * bigRadix + BigInt(n)
    }
    return num
  }

  private _bigIntToNumerals(num: bigint, length: number): number[] {
    const numerals = new Array(length)
    const bigRadix = BigInt(this.radix)
    let tempNum = num
    for (let i = length - 1; i >= 0; i--) {
      numerals[i] = Number(tempNum % bigRadix)
      tempNum /= bigRadix
    }
    return numerals
  }

  private _bigIntToBytes(num: bigint, numBytes: number): Uint8Array {
    const bytes = new Uint8Array(numBytes)
    let tempNum = num
    for (let i = numBytes - 1; i >= 0; i--) {
      bytes[i] = Number(tempNum & 0xffn)
      tempNum >>= 8n
    }
    return bytes
  }

  private _bytesToBigInt(bytes: Uint8Array): bigint {
    let num = 0n
    for (const byte of bytes) {
      num = (num << 8n) | BigInt(byte)
    }
    return num
  }

  /**
   * Implementación de PRF(X) según NIST SP 800-38G, Algoritmo 4.
   * Es un CBC-MAC con un IV de cero.
   */
  private _prf(data: Uint8Array): Uint8Array {
    let mac = new Uint8Array(16)
    const numBlocks = Math.ceil(data.length / 16)
    const currentBlock = new Uint8Array(16)

    for (let i = 0; i < numBlocks; i++) {
      const offset = i * 16
      currentBlock.fill(0)
      currentBlock.set(data.subarray(offset, offset + 16))

      for (let j = 0; j < 16; j++) {
        currentBlock[j] ^= mac[j]
      }
      mac = this.aes.encrypt(currentBlock)
    }
    return mac
  }

  // --- Lógica Principal de FF1 (Corregida según NIST SP 800-38Gr1) ---

  private _ff1(text: string, tweak: Uint8Array, isEncrypt: boolean): string {
    const n = text.length
    if (n < this.minLen || n > this.maxLen) {
      throw new Error(`La longitud del texto (${n}) debe estar entre ${this.minLen} y ${this.maxLen}.`)
    }

    const tLen = tweak.length
    const u = Math.floor(n / 2)
    const v = n - u
    const b = Math.ceil((v * Math.log2(this.radix)) / 8) || 1
    const d = 4 * Math.ceil(b / 4) + 4

    // Paso 5: Construir P.
    const P = new Uint8Array(16)
    P[0] = 1
    P[1] = 2
    P[2] = 1
    P[3] = (this.radix >> 8) & 0xff // [radix]^2 en big-endian
    P[4] = this.radix & 0xff
    P[5] = 10
    P[6] = u & 0xff
    P[7] = (n >> 24) & 0xff // [n]^4 en big-endian
    P[8] = (n >> 16) & 0xff
    P[9] = (n >> 8) & 0xff
    P[10] = n & 0xff
    P[11] = (tLen >> 24) & 0xff // [tLen]^4 en big-endian
    P[12] = (tLen >> 16) & 0xff
    P[13] = (tLen >> 8) & 0xff
    P[14] = tLen & 0xff

    let A = this._stringToNumerals(text.substring(0, u))
    let B = this._stringToNumerals(text.substring(u))

    const radix_u = BigInt(this.radix) ** BigInt(u)
    const radix_v = BigInt(this.radix) ** BigInt(v)

    const numRounds = 10
    for (let i = 0; i < numRounds; i++) {
      const round = isEncrypt ? i : numRounds - 1 - i
      const m = round % 2 === 0 ? u : v
      const radix_m = round % 2 === 0 ? radix_u : radix_v
      const prfInputBlock = isEncrypt ? B : A

      const qPadLen = (-tLen - b - 1) & 15
      const Q = new Uint8Array(tLen + qPadLen + 1 + b)
      Q.set(tweak)
      Q[tLen + qPadLen] = round
      const numPrfInput = this._numeralsToBigInt(prfInputBlock)
      Q.set(this._bigIntToBytes(numPrfInput, b), tLen + qPadLen + 1)

      const R = this._prf(Uint8Array.of(...P, ...Q))

      const S = new Uint8Array(d)
      S.set(R.subarray(0, Math.min(16, d))) // Copia segura

      const numSBlocks = Math.ceil(d / 16)
      if (numSBlocks > 1) {
        let bytesWritten = 16
        const tempBlock = new Uint8Array(16)
        for (let j = 1; j < numSBlocks; j++) {
          if (bytesWritten >= d) break

          tempBlock.set(R) // Empezar con R

          // XOR con [j]^16 sin DataView. [j]^16 son 12 ceros y 4 bytes de j.
          // Solo necesitamos hacer XOR en los últimos 4 bytes del bloque temporal.
          tempBlock[12] ^= (j >> 24) & 0xff
          tempBlock[13] ^= (j >> 16) & 0xff
          tempBlock[14] ^= (j >> 8) & 0xff
          tempBlock[15] ^= j & 0xff

          const encryptedBlock = this.aes.encrypt(tempBlock)

          const bytesToCopy = Math.min(16, d - bytesWritten)
          S.set(encryptedBlock.subarray(0, bytesToCopy), bytesWritten)
          bytesWritten += bytesToCopy
        }
      }

      const y = this._bytesToBigInt(S)

      let c_num: bigint
      if (isEncrypt) {
        const numA = this._numeralsToBigInt(A)
        c_num = (numA + y) % radix_m
      } else {
        const numB = this._numeralsToBigInt(B)
        c_num = (numB - y) % radix_m
        if (c_num < 0) {
          c_num += radix_m
        }
      }

      const C = this._bigIntToNumerals(c_num, m)

      if (isEncrypt) {
        A = B
        B = C
      } else {
        B = A
        A = C
      }
    }

    return this._numeralsToString(A.concat(B))
  }

  public encrypt(plaintext: string, tweak: Uint8Array = new Uint8Array(0)): string {
    return this._ff1(plaintext, tweak, true)
  }

  public decrypt(ciphertext: string, tweak: Uint8Array = new Uint8Array(0)): string {
    return this._ff1(ciphertext, tweak, false)
  }
}

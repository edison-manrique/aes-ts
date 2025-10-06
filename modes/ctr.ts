import { AES } from "../aes"

/**
 * Implementación del contador para el modo CTR.
 *
 * El contador mantiene un valor de 128 bits que se incrementa para cada bloque
 * de datos que se cifra. Puede inicializarse con un valor numérico o un array de bytes.
 *
 * Características principales:
 * - **Incremento**: Incrementa el valor en 1 para cada uso.
 * - **Flexibilidad**: Puede inicializarse con diferentes tipos de valores.
 * - **Seguridad**: Debe ser único para cada bloque cifrado con la misma clave.
 */
export class Counter {
  private _counter: Uint8Array

  /**
   * Inicializa el contador.
   * @param initialValue El valor inicial del contador, puede ser un número o un array de 16 bytes.
   */
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

  /**
   * Establece el valor del contador.
   * @param value El valor a establecer, debe ser un entero seguro.
   */
  setValue(value: number): void {
    if (!Number.isSafeInteger(value)) {
      throw new Error("Valor de contador inválido (debe ser un entero seguro)")
    }
    for (let i = 15; i >= 0; --i) {
      this._counter[i] = value % 256
      value = Math.floor(value / 256)
    }
  }

  /**
   * Incrementa el contador en 1.
   */
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

  /**
   * Obtiene los bytes del contador.
   * @returns Una copia de los bytes del contador.
   */
  get counterBytes(): Uint8Array {
    return this._counter
  }
}

/**
 * Implementación del modo de operación AES-CTR (Counter).
 *
 * CTR es un modo de operación que convierte un cifrador de bloques en un cifrador de flujo.
 * Opera generando una secuencia de claves pseudoaleatoria mediante el cifrado de valores
 * de contador incrementales, que luego se utilizan para enmascarar el texto plano mediante XOR.
 *
 * Características principales:
 * - **Cifrador de flujo**: Puede cifrar datos de cualquier tamaño sin necesidad de relleno.
 * - **Paralelizable**: Todos los bloques pueden cifrarse/descifrarse en paralelo.
 * - **Búsqueda aleatoria**: Se puede acceder a cualquier parte del texto cifrado sin procesar los bloques anteriores.
 * - **IV/Nonce requerido**: Requiere un valor de inicialización único para cada operación de cifrado.
 *
 * Consideraciones de seguridad:
 * - **Nonce único**: El nonce debe ser único para cada cifrado con la misma clave.
 * - **Sin autenticación**: CTR no proporciona autenticación; se debe usar con un MAC para AE.
 * - **Contador nunca debe repetirse**: La combinación (clave, contador) debe ser única para cada bloque.
 *
 * CTR es uno de los modos más utilizados actualmente debido a su eficiencia y propiedades deseables.
 * Es la base de muchos modos AEAD modernos como GCM.
 *
 * @example
 * ```typescript
 * const key = new Uint8Array(16); // Clave de 128 bits
 * const nonce = new Uint8Array(16);  // Nonce de 128 bits
 * const ctr = new ModeOfOperationCTR(key, nonce);
 * const plaintext = new TextEncoder().encode("Mensaje secreto");
 * const ciphertext = ctr.encrypt(plaintext);
 * const decrypted = ctr.decrypt(ciphertext); // ¡La misma operación!
 * ```
 *
 * @see [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
 * para la especificación oficial del modo CTR.
 */
export class ModeOfOperationCTR {
  public readonly description = "Counter"
  public readonly name = "ctr"
  private readonly aes: AES
  private readonly counter: Counter
  private remainingCounter: Uint8Array | null = null
  private remainingCounterIndex = 16

  /**
   * Inicializa el modo de operación CTR con una clave y un contador opcional.
   * @param key La clave de cifrado, debe ser de 16, 24 o 32 bytes (128, 192 o 256 bits).
   * @param counter El contador inicial, puede ser una instancia de Counter, un número o un array de 16 bytes.
   */
  constructor(key: Uint8Array, counter?: Counter | number | Uint8Array) {
    this.aes = new AES(key)
    if (counter instanceof Counter) {
      this.counter = counter
    } else {
      this.counter = new Counter(counter)
    }
  }

  /**
   * Cifra o descifra datos en modo CTR. La misma operación se usa para ambos propósitos.
   * @param plaintext El texto plano a cifrar (o texto cifrado a descifrar).
   * @returns El texto cifrado (o texto plano) del mismo tamaño que la entrada.
   */
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

  /**
   * Descifra datos en modo CTR. Esta operación es idéntica a la de cifrado.
   * @param ciphertext El texto cifrado a descifrar.
   * @returns El texto plano del mismo tamaño que el texto cifrado.
   */
  decrypt = this.encrypt
}
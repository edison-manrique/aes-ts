import { HighLevelAES, AesMode } from "../high-level"

// Función para medir el tiempo de ejecución
function measureTime(fn: () => void): number {
  const start = performance.now()
  fn()
  const end = performance.now()
  return end - start
}

// Función para formatear el resultado
function formatResult(mode: string, operation: string, timeMs: number, dataSize: number): string {
  const seconds = timeMs / 1000
  const megabytes = dataSize / (1024 * 1024)
  const mbps = megabytes / seconds
  return `${mode} ${operation}: ${mbps.toFixed(2)} MB/s (${megabytes.toFixed(2)} MB in ${seconds.toFixed(3)}s)`
}

// Para FPE-FF1, usaremos un texto de prueba en lugar de datos binarios
// Generar una cadena de números de 20000 dígitos
const TEST_DATA_LENGTH = 20000
let testData = ""
for (let i = 0; i < TEST_DATA_LENGTH; i++) {
  testData += Math.floor(Math.random() * 10)
}

// Clave de 256 bits
const key = new Uint8Array(32)
if (typeof crypto !== "undefined" && crypto.getRandomValues) {
  crypto.getRandomValues(key)
} else {
  for (let i = 0; i < key.length; i++) {
    key[i] = Math.floor(Math.random() * 256)
  }
}

// Tweak para FPE-FF1
const tweak = new Uint8Array(8)
if (typeof crypto !== "undefined" && crypto.getRandomValues) {
  crypto.getRandomValues(tweak)
} else {
  for (let i = 0; i < tweak.length; i++) {
    tweak[i] = Math.floor(Math.random() * 256)
  }
}

console.log(`Benchmarking FPE-FF1 mode with ${TEST_DATA_LENGTH} digits of data`)

// Crear instancia de HighLevelAES para FPE-FF1
// Nota: FPE-FF1 requiere un alfabeto, usaremos dígitos (0-9)
const fpeCipher = new HighLevelAES(AesMode.FPE_FF1, key)

// Benchmark de cifrado
console.log("Running encryption benchmark...")
const encryptTime = measureTime(() => {
  const encrypted = fpeCipher.encryptTextWithAlphabet(testData, "0123456789", { tweak })
})

console.log(`${"FPE-FF1"} ${"encryption"}: ${TEST_DATA_LENGTH} digits processed in ${(encryptTime / 1000).toFixed(3)}s`)

// Usar los mismos datos cifrados para el benchmark de descifrado
const encryptedData = fpeCipher.encryptTextWithAlphabet(testData, "0123456789", { tweak })

// Benchmark de descifrado
console.log("Running decryption benchmark...")
const decryptTime = measureTime(() => {
  const decrypted = fpeCipher.decryptTextWithAlphabet(encryptedData, "0123456789", { tweak })
})

console.log(`${"FPE-FF1"} ${"decryption"}: ${TEST_DATA_LENGTH} digits processed in ${(decryptTime / 1000).toFixed(3)}s`)

console.log("FPE-FF1 benchmark completed.")

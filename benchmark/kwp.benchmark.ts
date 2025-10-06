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

// Tamaño de datos para benchmark (1 MB)
const DATA_SIZE = 1 * 1024 * 1024
const testData = new Uint8Array(DATA_SIZE)
// Llenar con datos aleatorios
if (typeof crypto !== "undefined" && crypto.getRandomValues) {
  crypto.getRandomValues(testData)
} else {
  // Fallback para entornos sin crypto
  for (let i = 0; i < testData.length; i++) {
    testData[i] = Math.floor(Math.random() * 256)
  }
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

console.log(`Benchmarking KWP mode with ${DATA_SIZE / (1024 * 1024)} MB of data`)

// Crear instancia de HighLevelAES para KWP
const kwpCipher = new HighLevelAES(AesMode.KWP, key)

// Benchmark de cifrado (envoltura)
console.log("Running key wrapping benchmark...")
const encryptTime = measureTime(() => {
  const encrypted = kwpCipher.encrypt(testData)
})

console.log(formatResult("KWP", "wrapping", encryptTime, DATA_SIZE))

// Usar los mismos datos cifrados para el benchmark de descifrado
const encryptedData = kwpCipher.encrypt(testData)

// Benchmark de descifrado (desenvoltura)
console.log("Running key unwrapping benchmark...")
const decryptTime = measureTime(() => {
  const decrypted = kwpCipher.decrypt(encryptedData.ciphertext)
})

console.log(formatResult("KWP", "unwrapping", decryptTime, DATA_SIZE))

console.log("KWP benchmark completed.")

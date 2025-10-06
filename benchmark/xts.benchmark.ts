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

// Tamaño de datos para benchmark (10 MB)
const DATA_SIZE = 10 * 1024 * 1024
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

// Clave de 512 bits (64 bytes) para XTS
const key = new Uint8Array(64)
if (typeof crypto !== "undefined" && crypto.getRandomValues) {
  crypto.getRandomValues(key)
} else {
  for (let i = 0; i < key.length; i++) {
    key[i] = Math.floor(Math.random() * 256)
  }
}

// Tweak de 16 bytes para XTS
const tweak = new Uint8Array(16)
if (typeof crypto !== "undefined" && crypto.getRandomValues) {
  crypto.getRandomValues(tweak)
} else {
  for (let i = 0; i < tweak.length; i++) {
    tweak[i] = Math.floor(Math.random() * 256)
  }
}

console.log(`Benchmarking XTS mode with ${DATA_SIZE / (1024 * 1024)} MB of data`)

// Crear instancia de HighLevelAES para XTS
const xtsCipher = new HighLevelAES(AesMode.XTS, key)

// Benchmark de cifrado
console.log("Running encryption benchmark...")
const encryptTime = measureTime(() => {
  const encrypted = xtsCipher.encrypt(testData, { tweak })
})

console.log(formatResult("XTS", "encryption", encryptTime, DATA_SIZE))

// Usar los mismos datos cifrados para el benchmark de descifrado
const encryptedData = xtsCipher.encrypt(testData, { tweak })

// Benchmark de descifrado
console.log("Running decryption benchmark...")
const decryptTime = measureTime(() => {
  const decrypted = xtsCipher.decrypt(encryptedData.ciphertext, { tweak })
})

console.log(formatResult("XTS", "decryption", decryptTime, DATA_SIZE))

console.log("XTS benchmark completed.")

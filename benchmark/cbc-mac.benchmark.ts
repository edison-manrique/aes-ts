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

// Clave de 256 bits
const key = new Uint8Array(32)
if (typeof crypto !== "undefined" && crypto.getRandomValues) {
  crypto.getRandomValues(key)
} else {
  for (let i = 0; i < key.length; i++) {
    key[i] = Math.floor(Math.random() * 256)
  }
}

console.log(`Benchmarking CBC-MAC mode with ${DATA_SIZE / (1024 * 1024)} MB of data`)

// Crear instancia de HighLevelAES para CBC-MAC
const cbcMacCipher = new HighLevelAES(AesMode.CBC_MAC, key)

// Benchmark de generación de tag
console.log("Running tag generation benchmark...")
const tagTime = measureTime(() => {
  const result = cbcMacCipher.encrypt(testData)
})

console.log(formatResult("CBC-MAC", "tag generation", tagTime, DATA_SIZE))

// Usar los mismos datos para el benchmark de verificación
const tagData = cbcMacCipher.encrypt(testData)

// Benchmark de verificación de tag (simulando verificación)
console.log("Running tag verification benchmark...")
const verifyTime = measureTime(() => {
  // Simular verificación usando el mismo método de generación de tag
  const result = cbcMacCipher.encrypt(testData)
})

console.log(formatResult("CBC-MAC", "tag verification", verifyTime, DATA_SIZE))

console.log("CBC-MAC benchmark completed.")

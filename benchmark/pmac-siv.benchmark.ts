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

// Nonce para PMAC-SIV
const nonce = new Uint8Array(12)
if (typeof crypto !== "undefined" && crypto.getRandomValues) {
  crypto.getRandomValues(nonce)
} else {
  for (let i = 0; i < nonce.length; i++) {
    nonce[i] = Math.floor(Math.random() * 256)
  }
}

console.log(`Benchmarking PMAC-SIV mode with ${DATA_SIZE / (1024 * 1024)} MB of data`)

// Crear instancia de HighLevelAES para PMAC-SIV
const pmacSivCipher = new HighLevelAES(AesMode.PMAC_SIV, key)

// Benchmark de cifrado
console.log("Running encryption benchmark...")
const encryptTime = measureTime(() => {
  const encrypted = pmacSivCipher.encrypt(testData, { nonce })
})

console.log(formatResult("PMAC-SIV", "encryption", encryptTime, DATA_SIZE))

// Usar los mismos datos cifrados para el benchmark de descifrado
const encryptedData = pmacSivCipher.encrypt(testData, { nonce })

// Benchmark de descifrado
console.log("Running decryption benchmark...")
const decryptTime = measureTime(() => {
  const decrypted = pmacSivCipher.decrypt(encryptedData.ciphertext, {
    nonce: encryptedData.iv,
    tag: encryptedData.tag
  })
})

console.log(formatResult("PMAC-SIV", "decryption", decryptTime, DATA_SIZE))

console.log("PMAC-SIV benchmark completed.")

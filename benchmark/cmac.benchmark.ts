import { HighLevelAES, AesMode } from "../high-level"

// Function to measure execution time
function measureTime(fn: () => void): number {
  const start = performance.now()
  fn()
  const end = performance.now()
  return end - start
}

// Function to format the result
function formatResult(mode: string, operation: string, timeMs: number, dataSize: number): string {
  const seconds = timeMs / 1000
  const megabytes = dataSize / (1024 * 1024)
  const mbps = megabytes / seconds
  return `${mode} ${operation}: ${mbps.toFixed(2)} MB/s (${megabytes.toFixed(2)} MB in ${seconds.toFixed(3)}s)`
}

// Data size for benchmark (10 MB)
const DATA_SIZE = 10 * 1024 * 1024
const testData = new Uint8Array(DATA_SIZE)
// Fill with random data
if (typeof crypto !== "undefined" && crypto.getRandomValues) {
  crypto.getRandomValues(testData)
} else {
  // Fallback for environments without crypto
  for (let i = 0; i < testData.length; i++) {
    testData[i] = Math.floor(Math.random() * 256)
  }
}

// 256-bit key
const key = new Uint8Array(32)
if (typeof crypto !== "undefined" && crypto.getRandomValues) {
  crypto.getRandomValues(key)
} else {
  for (let i = 0; i < key.length; i++) {
    key[i] = Math.floor(Math.random() * 256)
  }
}

console.log(`Benchmarking CMAC mode with ${DATA_SIZE / (1024 * 1024)} MB of data`)

// Create HighLevelAES instance for CMAC
const cmacCipher = new HighLevelAES(AesMode.CMAC, key)

// Benchmark tag generation
console.log("Running tag generation benchmark...")
const tagTime = measureTime(() => {
  const result = cmacCipher.encrypt(testData)
})

console.log(formatResult("CMAC", "tag generation", tagTime, DATA_SIZE))

// Use the same data for verification benchmark
const tagData = cmacCipher.encrypt(testData)

// Benchmark tag verification (simulating verification)
console.log("Running tag verification benchmark...")
const verifyTime = measureTime(() => {
  // Simulate verification using the same tag generation method
  const result = cmacCipher.encrypt(testData)
})

console.log(formatResult("CMAC", "tag verification", verifyTime, DATA_SIZE))

console.log("CMAC benchmark completed.")
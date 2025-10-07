import { exec } from "child_process"
import { promisify } from "util"

const execAsync = promisify(exec)

// Lista de todos los modos de operación
const modes = [
  "ecb",
  "cbc",
  "ctr",
  "cfb",
  "ofb",
  "gcm",
  "ccm",
  "eax",
  "cwc",
  "gcm-siv",
  "ocb",
  "xts",
  "kw",
  "kwp",
  "fpe-ff1",
  "hybrid-ctr",
  "cbc-mac",
  "cmac",
  "pmac-siv"
]

async function runAllBenchmarks() {
  console.log("Running all AES mode benchmarks...\n")

  for (const mode of modes) {
    try {
      console.log(`Running benchmark for ${mode.toUpperCase()} mode...`)
      const { stdout, stderr } = await execAsync(`bun run ${mode}.benchmark.ts`, {
        cwd: __dirname
      })

      if (stdout) {
        console.log(stdout)
      }

      if (stderr) {
        console.error(stderr)
      }

      console.log(`Completed benchmark for ${mode.toUpperCase()} mode.\n`)
    } catch (error) {
      console.error(`Error running benchmark for ${mode.toUpperCase()} mode:`, error)
    }
  }

  console.log("All benchmarks completed.")
}

// Ejecutar todos los benchmarks si este archivo se ejecuta directamente
if (require.main === module) {
  runAllBenchmarks()
}

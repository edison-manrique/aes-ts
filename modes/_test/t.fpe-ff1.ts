import { ModeOfOperationFPE_FF1 } from "../fpe-ff1" // Ajusta la ruta si es necesario

// --- Datos de Prueba del NIST SP 800-38Gr1 (Apéndice D.1) ---
const key = Uint8Array.fromHex("2B7E151628AED2A6ABF7158809CF4F3C")
const alphabet = "0123456789"
const tweakBytes = Uint8Array.fromHex("AED1232FC0")

const plaintextString = "0123456789"

// Crea una instancia de la clase FPE.
const fpe = new ModeOfOperationFPE_FF1(key, alphabet)

console.log("--- Prueba de Cifrado y Descifrado AES-FPE (FF1) ---")

// --- Cifrado ---
const ciphertext = fpe.encrypt(plaintextString, tweakBytes)

console.log(`Modo:              ${fpe.description}`)
console.log(`Clave:             ${key.toHex()}`)
console.log(`Alfabeto:          "${alphabet}" (radix ${alphabet.length})`)
console.log(`Tweak:             (vacío)`)
console.log(`Texto Plano:       ${plaintextString}`)
console.log(`Texto Cifrado:     ${ciphertext}`)
console.log("\n")


// --- Descifrado (Caso de Éxito) ---
console.log("--- Intentando descifrado con datos y tweak correctos ---")
const decryptedString = fpe.decrypt(ciphertext, tweakBytes)

console.log(`Resultado:         Éxito`)
console.log(`Texto Descifrado:  ${decryptedString}`)
// Verificación final
if (decryptedString === plaintextString) {
  console.log("VERIFICACIÓN:      El texto descifrado coincide con el original. ✅")
} else {
  console.error("VERIFICACIÓN:      ¡ERROR! El texto descifrado NO coincide con el original. ❌")
}
console.log("\n")

// --- Prueba de Corrupción de Datos (Tweak Incorrecto) ---
console.log("--- Intentando descifrado con TWEAK INCORRECTO ---")
const wrongTweakBytes = Uint8Array.fromHex("DEADBEEF")

const failedDecryption1 = fpe.decrypt(ciphertext, wrongTweakBytes)

if (failedDecryption1 !== plaintextString) {
  console.log("Resultado:         El descifrado produjo texto corrupto, como se esperaba. ✅")
  console.log(`Texto Corrupto:    ${failedDecryption1}`)
} else {
  console.error("Resultado:         El descifrado tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}

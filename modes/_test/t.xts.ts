import { ModeOfOperationXTS } from "../xts"

// --- Datos de Prueba ---
// La clave para XTS debe ser de 32 bytes (para AES-128-XTS) o 64 bytes (para AES-256-XTS).
// Usaremos una clave de 32 bytes, que internamente se divide en dos claves de 16 bytes.
const key = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f])
// El "Tweak" para XTS es un valor de 16 bytes que representa la unidad de datos (ej. el número de sector del disco).
const tweak = new Uint8Array([0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb])

// Crea una instancia de la clase XTS.
const xts = new ModeOfOperationXTS(key)

// Datos a cifrar. Usaremos un texto que NO sea múltiplo de 16 para probar el "ciphertext stealing".
// Longitud: 45 bytes (2 bloques completos + 1 bloque parcial de 13 bytes).
const plaintextString = "XTS es el estándar para cifrado de discos."
const plaintextBytes = new TextEncoder().encode(plaintextString)

console.log("--- Prueba de Cifrado y Descifrado AES-XTS ---")

// --- Cifrado ---
// XTS no produce una etiqueta de autenticación separada.
const ciphertext = xts.encrypt(plaintextBytes, tweak)

console.log(`Modo:              AES - ${xts.description}`)
console.log(`Clave:             ${key.toHex()}`)
console.log(`Tweak (Sector):    ${tweak.toHex()}`)
console.log(`Texto Plano:       ${plaintextString}`)
console.log(`Texto Cifrado:     ${ciphertext.toBase64()}`)
console.log("\n")

// --- Descifrado (Caso de Éxito) ---
console.log("--- Intentando descifrado con datos y tweak correctos ---")
const decryptedPlaintext = xts.decrypt(ciphertext, tweak)
const decryptedString = new TextDecoder().decode(decryptedPlaintext)

console.log(`Resultado:         Éxito`)
console.log(`Texto Descifrado:  ${decryptedString}`)
// Verificación final
if (decryptedString === plaintextString) {
  console.log("VERIFICACIÓN:      El texto descifrado coincide con el original. ✅")
} else {
  console.error("VERIFICACIÓN:      ¡ERROR! El texto descifrado NO coincide. ❌")
}
console.log("\n")

// --- Prueba de Corrupción de Datos (Texto Cifrado Alterado) ---
console.log("--- Intentando descifrado con TEXTO CIFRADO ALTERADO ---")
const tamperedCiphertext = new Uint8Array(ciphertext)
tamperedCiphertext[5] ^= 0xff // Alterar un byte del texto cifrado.

const failedDecryption1 = xts.decrypt(tamperedCiphertext, tweak)
const failedString1 = new TextDecoder().decode(failedDecryption1)

if (failedString1 !== plaintextString) {
  console.log("Resultado:         El descifrado produjo texto corrupto, como se esperaba. ✅")
  console.log(`Texto Corrupto:    ${failedString1}`)
} else {
  console.error("Resultado:         El descifrado tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}
console.log("\n")

// --- Prueba de Corrupción de Datos (Tweak Alterado) ---
console.log("--- Intentando descifrado con TWEAK ALTERADO ---")
const tamperedTweak = new Uint8Array(tweak)
tamperedTweak[0] ^= 0xff // Alterar el primer byte del tweak (cambiar de sector).

const failedDecryption2 = xts.decrypt(ciphertext, tamperedTweak)
const failedString2 = new TextDecoder().decode(failedDecryption2)

if (failedString2 !== plaintextString) {
  console.log("Resultado:         El descifrado produjo texto corrupto, como se esperaba. ✅")
  console.log(`Texto Corrupto:    ${failedString2}`)
} else {
  console.error("Resultado:         El descifrado tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}

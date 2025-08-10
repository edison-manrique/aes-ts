import { ModeOfOperationCWC } from "../cwc"

// --- Datos de Prueba ---
// La clave para CWC debe ser de 16 o 32 bytes (AES-128 o AES-256). Usaremos una clave de 16 bytes.
const key = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10])
// El nonce para CWC debe tener 12 bytes (96 bits).
const nonce = new Uint8Array([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0])

// Crea una instancia de la clase CWC. La clave se pasa al constructor.
const cwc = new ModeOfOperationCWC(key)

// Datos a cifrar
const plaintextString = "Este es un mensaje secreto para la prueba de CWC."
const associatedDataString = "Datos autenticados adicionales"
const plaintextBytes = new TextEncoder().encode(plaintextString)
const associatedData = new TextEncoder().encode(associatedDataString)

console.log("--- Prueba de Cifrado y Descifrado AES-CWC ---")

// --- Cifrado ---
// Cifra los datos y genera la etiqueta. El nonce se pasa a este método.
const { ciphertext, tag } = cwc.encrypt(plaintextBytes, nonce, associatedData)

console.log(`Modo:              AES - ${cwc.description}`)
console.log(`Clave:             ${key.toHex()}`)
console.log(
  `Nonce:             ${Array.from(nonce)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}`
)
console.log(`Texto Plano:       ${plaintextString}`)
console.log(`Datos Asociados:   ${associatedDataString}`)
console.log(`Texto Cifrado:     ${ciphertext.toBase64()}`)
console.log(`Etiqueta (Tag):    ${tag.toHex()}`)
console.log("\n")

// --- Descifrado (Caso de Éxito) ---
console.log("--- Intentando descifrado con datos y etiqueta correctos ---")
const decryptedPlaintext = cwc.decrypt(ciphertext, tag, nonce, associatedData)

if (decryptedPlaintext) {
  const decryptedString = new TextDecoder().decode(decryptedPlaintext)
  console.log(`Resultado:         Éxito`)
  console.log(`Texto Descifrado:  ${decryptedString}`)
  // Verificación final
  if (decryptedString === plaintextString) {
    console.log("VERIFICACIÓN:      El texto descifrado coincide con el original. ✅")
  } else {
    console.error("VERIFICACIÓN:    ¡ERROR! El texto descifrado NO coincide. ❌")
  }
} else {
  console.error("Resultado:     ¡Fallo de autenticación inesperado! ❌")
}
console.log("\n")

// --- Prueba de Fallo de Autenticación (Etiqueta Alterada) ---
console.log("--- Intentando descifrado con ETIQUETA ALTERADA ---")
const tamperedTag = new Uint8Array(tag)
tamperedTag[0] ^= 0xff // Alterar el primer byte de la etiqueta

const failedDecryption1 = cwc.decrypt(ciphertext, tamperedTag, nonce, associatedData)

if (failedDecryption1 === null) {
  console.log("Resultado:       Fallo de autenticación como se esperaba. ✅")
} else {
  console.error("Resultado:     El descifrado tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}
console.log("\n")

// --- Prueba de Fallo de Autenticación (Datos Asociados Alterados) ---
console.log("--- Intentando descifrado con DATOS ASOCIADOS ALTERADOS ---")
const tamperedAssociatedData = new TextEncoder().encode("Estos no son los datos correctos")

const failedDecryption2 = cwc.decrypt(ciphertext, tag, nonce, tamperedAssociatedData)

if (failedDecryption2 === null) {
  console.log("Resultado:       Fallo de autenticación como se esperaba. ✅")
} else {
  console.error("Resultado:     El descifrado tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}

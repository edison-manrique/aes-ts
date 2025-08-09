import { ModeOfOperationGCM_SIV } from "../gcm-siv"

// --- Datos de Prueba ---
// La clave para GCM-SIV debe ser de 16 o 32 bytes (AES-128 o AES-256). Usaremos una clave de 32 bytes.
const key = new Uint8Array([0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10])
// El nonce para GCM-SIV debe tener 12 bytes (96 bits).
const nonce = new Uint8Array([0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88])

// Crea una instancia de la clase GCM-SIV. La clave se pasa al constructor.
const gcmSiv = new ModeOfOperationGCM_SIV(key)

// Datos a cifrar
const plaintextString = "¡Mensaje secreto resistente al reuso de nonces!"
const associatedDataString = "Datos autenticados pero no cifrados"
const plaintextBytes = new TextEncoder().encode(plaintextString)
const associatedData = new TextEncoder().encode(associatedDataString)

console.log("--- Prueba de Cifrado y Descifrado AES-GCM-SIV ---")

// --- Cifrado ---
// Cifra los datos y genera la etiqueta. El nonce se pasa a este método.
const { ciphertext, tag } = gcmSiv.encrypt(plaintextBytes, nonce, associatedData)

console.log(`Modo:              AES - ${gcmSiv.description}`)
console.log(`Clave:             ${key.toHex()}`)
console.log(`Nonce:             ${nonce.toHex()}`)
console.log(`Texto Plano:       ${plaintextString}`)
console.log(`Datos Asociados:   ${associatedDataString}`)
console.log(`Texto Cifrado:     ${ciphertext.toBase64()}`)
console.log(`Etiqueta (Tag):    ${tag.toHex()}`)
console.log("\n")

// --- Descifrado (Caso de Éxito) ---
console.log("--- Intentando descifrado con datos y etiqueta correctos ---")
const decryptedPlaintext = gcmSiv.decrypt(ciphertext, tag, nonce, associatedData)

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

const failedDecryption1 = gcmSiv.decrypt(ciphertext, tamperedTag, nonce, associatedData)

if (failedDecryption1 === null) {
  console.log("Resultado:       Fallo de autenticación como se esperaba. ✅")
} else {
  console.error("Resultado:     El descifrado tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}
console.log("\n")

// --- Prueba de Fallo de Autenticación (Datos Asociados Alterados) ---
console.log("--- Intentando descifrado con DATOS ASOCIADOS ALTERADOS ---")
const tamperedAssociatedData = new TextEncoder().encode("Estos no son los datos correctos")

const failedDecryption2 = gcmSiv.decrypt(ciphertext, tag, nonce, tamperedAssociatedData)

if (failedDecryption2 === null) {
  console.log("Resultado:       Fallo de autenticación como se esperaba. ✅")
} else {
  console.error("Resultado:     El descifrado tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}

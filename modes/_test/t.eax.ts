import { ModeOfOperationEAX } from "../eax"

// Usaremos una clave de 16 bytes (AES-128).
const key = new Uint8Array([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
// El Nonce para EAX puede tener cualquier longitud.
const nonce = new Uint8Array([0x62, 0xec, 0x61, 0xb2, 0xa0, 0x92, 0x56, 0x93, 0x24, 0x8f, 0x64, 0x2e])
// El tamaño de la etiqueta (tag) es de 16 bytes (128 bits) por defecto.
const tagSize = 16

// Crea una instancia de la clase EAX.
const eax = new ModeOfOperationEAX(key, tagSize)

// Datos a cifrar
const plaintextString = "EAX es un modo de cifrado autenticado de dos pasadas."
const associatedDataString = "Metadatos autenticados para EAX"
const plaintextBytes = new TextEncoder().encode(plaintextString)
const associatedData = new TextEncoder().encode(associatedDataString)

console.log("--- Prueba de Cifrado y Descifrado AES-EAX ---")

// --- Cifrado ---
const { ciphertext, tag } = eax.encrypt(plaintextBytes, nonce, associatedData)

console.log(`Modo:              AES - ${eax.description}`)
console.log(`Clave:             ${key.toHex()}`)
console.log(`Nonce:             ${nonce.toHex()}`)
console.log(`Texto Plano:       ${plaintextString}`)
console.log(`Datos Asociados:   ${associatedDataString}`)
console.log(`Texto Cifrado:     ${ciphertext.toBase64()}`)
console.log(`Etiqueta (Tag):    ${tag.toHex()}`)
console.log("\n")

// --- Descifrado (Caso de Éxito) ---
console.log("--- Intentando descifrado con datos y etiqueta correctos ---")
const decryptedPlaintext = eax.decrypt(ciphertext, tag, nonce, associatedData)

if (decryptedPlaintext) {
  const decryptedString = new TextDecoder().decode(decryptedPlaintext)
  console.log(`Resultado:         Éxito`)
  console.log(`Texto Descifrado:  ${decryptedString}`)
  // Verificación final
  if (decryptedString === plaintextString) {
    console.log("VERIFICACIÓN:      El texto descifrado coincide con el original. ✅")
  } else {
    console.error("VERIFICACIÓN:      ¡ERROR! El texto descifrado NO coincide. ❌")
  }
} else {
  console.error("Resultado:         ¡Fallo de autenticación inesperado! ❌")
}
console.log("\n")

// --- Prueba de Fallo de Autenticación (Etiqueta Alterada) ---
console.log("--- Intentando descifrado con ETIQUETA ALTERADA ---")
const tamperedTag = new Uint8Array(tag)
tamperedTag[0] ^= 0xff // Alterar el primer byte de la etiqueta

const failedDecryption1 = eax.decrypt(ciphertext, tamperedTag, nonce, associatedData)

if (failedDecryption1 === null) {
  console.log("Resultado:         Fallo de autenticación como se esperaba. ✅")
} else {
  console.error("Resultado:         El descifrado tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}
console.log("\n")

// --- Prueba de Fallo de Autenticación (Datos Asociados Alterados) ---
console.log("--- Intentando descifrado con DATOS ASOCIADOS ALTERADOS ---")
const tamperedAssociatedData = new TextEncoder().encode("Estos no son los datos correctos")

const failedDecryption2 = eax.decrypt(ciphertext, tag, nonce, tamperedAssociatedData)

if (failedDecryption2 === null) {
  console.log("Resultado:         Fallo de autenticación como se esperaba. ✅")
} else {
  console.error("Resultado:         El descifrado tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}

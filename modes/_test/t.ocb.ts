// Asume que este archivo está en una carpeta de pruebas. Ajusta la ruta de importación según sea necesario.
import { ModeOfOperationOCB } from "../ocb"

// --- Datos de Prueba ---
// La clave para AES-OCB debe ser de 16, 24 o 32 bytes. Usaremos una clave de 16 bytes (AES-128).
const key = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
// El Nonce para OCB puede tener entre 1 y 15 bytes. Usaremos un nonce común de 12 bytes.
const nonce = new Uint8Array([0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb])
// El tamaño de la etiqueta (tag) es de 16 bytes (128 bits) por defecto, lo cual es lo más seguro.
const tagSize = 16

// Crea una instancia de la clase de modo OCB.
const ocb = new ModeOfOperationOCB(key, tagSize)

// Datos a cifrar
const plaintextString = "OCB es eficiente y totalmente paralelizable."
const associatedDataString = "Metadatos autenticados para OCB"
const plaintextBytes = new TextEncoder().encode(plaintextString)
const associatedData = new TextEncoder().encode(associatedDataString)

console.log("--- Prueba de Cifrado y Descifrado AES-OCB ---")

// --- Cifrado ---
// Cifra los datos y genera la etiqueta de autenticación.
const { ciphertext, tag } = ocb.encrypt(plaintextBytes, nonce, associatedData)

console.log(`Modo:              AES - ${ocb.description}`)
console.log(`Clave:             ${key.toHex()}`)
console.log(`Nonce:             ${nonce.toHex()}`)
console.log(`Texto Plano:       ${plaintextString}`)
console.log(`Datos Asociados:   ${associatedDataString}`)
console.log(`Texto Cifrado:     ${ciphertext.toBase64()}`)
console.log(`Etiqueta (Tag):    ${tag.toHex()}`)
console.log("\n")

// --- Descifrado (Caso de Éxito) ---
console.log("--- Intentando descifrado con datos y etiqueta correctos ---")
const decryptedPlaintext = ocb.decrypt(ciphertext, tag, nonce, associatedData)

if (decryptedPlaintext) {
  const decryptedString = new TextDecoder().decode(decryptedPlaintext)
  console.log(`Resultado:         Éxito`)
  console.log(`Texto Descifrado:  ${decryptedString}`)
  // Verificación final
  if (decryptedString === plaintextString) {
    console.log("VERIFICACIÓN:      El texto descifrado coincide con el original. ✅")
  } else {
    console.error("VERIFICACIÓN:     ¡ERROR! El texto descifrado NO coincide. ❌")
  }
} else {
  console.error("Resultado:         ¡Fallo de autenticación inesperado! ❌")
}
console.log("\n")

// --- Prueba de Fallo de Autenticación (Texto Cifrado Alterado) ---
console.log("--- Intentando descifrado con TEXTO CIFRADO ALTERADO ---")
const tamperedCiphertext = new Uint8Array(ciphertext)
// Alterar un byte del texto cifrado (si no está vacío)
if (tamperedCiphertext.length > 0) {
  tamperedCiphertext[0] ^= 0xff
}

const failedDecryption1 = ocb.decrypt(tamperedCiphertext, tag, nonce, associatedData)

if (failedDecryption1 === null) {
  console.log("Resultado:         Fallo de autenticación como se esperaba. ✅")
} else {
  console.error("Resultado:         El descifrado tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}
console.log("\n")

// --- Prueba de Fallo de Autenticación (Etiqueta Alterada) ---
console.log("--- Intentando descifrado con ETIQUETA ALTERADA ---")
const tamperedTag = new Uint8Array(tag)
tamperedTag[0] ^= 0xff // Alterar el primer byte de la etiqueta

const failedDecryption2 = ocb.decrypt(ciphertext, tamperedTag, nonce, associatedData)

if (failedDecryption2 === null) {
  console.log("Resultado:         Fallo de autenticación como se esperaba. ✅")
} else {
  console.error("Resultado:         El descifrado tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}
console.log("\n")

// --- Prueba de Fallo de Autenticación (Datos Asociados Alterados) ---
console.log("--- Intentando descifrado con DATOS ASOCIADOS ALTERADOS ---")
const tamperedAssociatedData = new TextEncoder().encode("Estos no son los datos correctos")

const failedDecryption3 = ocb.decrypt(ciphertext, tag, nonce, tamperedAssociatedData)

if (failedDecryption3 === null) {
  console.log("Resultado:         Fallo de autenticación como se esperaba. ✅")
} else {
  console.error("Resultado:         El descifrado tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}

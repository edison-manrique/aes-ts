import { ModeOfOperationCBC_MAC } from "../cbc-mac"

// --- Datos de Prueba ---
// Usaremos una clave de 16 bytes (AES-128).
const key = new Uint8Array([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])

// Crea una instancia de la clase CBC-MAC.
const cbcMac = new ModeOfOperationCBC_MAC(key)

// --- Prueba 1: Mensaje que requiere relleno ---
console.log("--- Prueba de Autenticación AES-CBC-MAC (con relleno) ---")

// Datos a autenticar
const messageString1 = "Este es un mensaje para autenticar."
const messageBytes1 = new TextEncoder().encode(messageString1)

// --- Generación de Etiqueta ---
const generatedTag1 = cbcMac.generateTag(messageBytes1)

console.log(`Modo:              AES - ${cbcMac.description}`)
console.log(`Clave:             ${key.toHex()}`)
console.log(`Mensaje:           "${messageString1}"`)
console.log(`Etiqueta Generada: ${generatedTag1.toHex()}`)
console.log("\n")

// --- Verificación (Caso de Éxito) ---
console.log("--- Intentando verificación con mensaje y etiqueta correctos ---")
const isVerified1 = cbcMac.verifyTag(messageBytes1, generatedTag1)

if (isVerified1) {
  console.log("Resultado:         Éxito. La etiqueta es válida para el mensaje. ✅")
} else {
  console.error("Resultado:         ¡Fallo de verificación inesperado! ❌")
}
console.log("\n")

// --- Prueba de Fallo de Integridad (Mensaje Alterado) ---
console.log("--- Intentando verificación con MENSAJE ALTERADO ---")
const tamperedMessage = new Uint8Array(messageBytes1)
tamperedMessage[0] ^= 0xff // Alterar el primer byte del mensaje

const isVerifiedTamperedMessage = cbcMac.verifyTag(tamperedMessage, generatedTag1)

if (!isVerifiedTamperedMessage) {
  console.log("Resultado:         Fallo de verificación como se esperaba. ✅")
} else {
  console.error("Resultado:         La verificación tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}
console.log("\n")

// --- Prueba de Fallo de Integridad (Etiqueta Alterada) ---
console.log("--- Intentando verificación con ETIQUETA ALTERADA ---")
const tamperedTag = new Uint8Array(generatedTag1)
tamperedTag[0] ^= 0xff // Alterar el primer byte de la etiqueta

const isVerifiedTamperedTag = cbcMac.verifyTag(messageBytes1, tamperedTag)

if (!isVerifiedTamperedTag) {
  console.log("Resultado:         Fallo de verificación como se esperaba. ✅")
} else {
  console.error("Resultado:         La verificación tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}
console.log("\n")

// --- Prueba 2: Mensaje que es múltiplo de 16 bytes ---
console.log("--- Prueba con Mensaje Múltiplo de 16 bytes (sin relleno) ---")

// Mensaje de 32 bytes de longitud
const messageString2 = "Este es un mensaje de 32 bytes"
const messageBytes2 = new TextEncoder().encode(messageString2)

const generatedTag2 = cbcMac.generateTag(messageBytes2)
console.log(`Mensaje:           "${messageString2}"`)
console.log(`Etiqueta Generada: ${generatedTag2.toHex()}`)

const isVerified2 = cbcMac.verifyTag(messageBytes2, generatedTag2)
if (isVerified2) {
  console.log("Resultado:         Éxito. La etiqueta es válida para el mensaje. ✅")
} else {
  console.error("Resultado:         ¡Fallo de verificación inesperado! ❌")
}

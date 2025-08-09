import { ModeOfOperationPMAC_SIV } from "../pmac-siv"

// Usaremos una clave de 16 bytes (AES-128).
const key = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
// El Nonce para PMAC-SIV puede tener cualquier longitud.
const nonce = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
// El tamaño de la etiqueta (tag) es de 16 bytes (128 bits) por defecto.
const tagSize = 16

// Crea una instancia de la clase PMAC-SIV.
const pmacSiv = new ModeOfOperationPMAC_SIV(key, tagSize)

// Datos a cifrar
const plaintextString = "PMAC-SIV es resistente al uso indebido del nonce."
const associatedDataString = "Metadatos autenticados para PMAC-SIV"
const plaintextBytes = new TextEncoder().encode(plaintextString)
const associatedData = new TextEncoder().encode(associatedDataString)

console.log("--- Prueba de Cifrado y Descifrado AES-PMAC-SIV ---")

// --- Cifrado ---
// La salida incluye un 'iv_tag' que es tanto el IV sintético como la etiqueta.
const { ciphertext, iv_tag } = pmacSiv.encrypt(plaintextBytes, nonce, associatedData)

console.log(`Modo:              AES - ${pmacSiv.description}`)
console.log(`Clave:             ${key.toHex()}`)
console.log(`Nonce:             ${nonce.toHex()}`)
console.log(`Texto Plano:       ${plaintextString}`)
console.log(`Datos Asociados:   ${associatedDataString}`)
console.log(`Texto Cifrado:     ${ciphertext.toBase64()}`)
console.log(`IV/Etiqueta:       ${iv_tag.toHex()}`)
console.log("\n")

// --- Descifrado (Caso de Éxito) ---
console.log("--- Intentando descifrado con datos e IV/Etiqueta correctos ---")
const decryptedPlaintext = pmacSiv.decrypt(ciphertext, iv_tag, nonce, associatedData)

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

// --- Prueba de Fallo de Autenticación (IV/Etiqueta Alterada) ---
console.log("--- Intentando descifrado con IV/ETIQUETA ALTERADA ---")
const tampered_iv_tag = new Uint8Array(iv_tag)
tampered_iv_tag[0] ^= 0xff // Alterar el primer byte del IV/Tag

const failedDecryption1 = pmacSiv.decrypt(ciphertext, tampered_iv_tag, nonce, associatedData)

if (failedDecryption1 === null) {
  console.log("Resultado:         Fallo de autenticación como se esperaba. ✅")
} else {
  console.error("Resultado:         El descifrado tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}
console.log("\n")

// --- Prueba de Fallo de Autenticación (Texto Cifrado Alterado) ---
console.log("--- Intentando descifrado con TEXTO CIFRADO ALTERADO ---")
const tamperedCiphertext = new Uint8Array(ciphertext)
if (tamperedCiphertext.length > 0) tamperedCiphertext[0] ^= 0xff

const failedDecryption2 = pmacSiv.decrypt(tamperedCiphertext, iv_tag, nonce, associatedData)

if (failedDecryption2 === null) {
  console.log("Resultado:         Fallo de autenticación como se esperaba. ✅")
} else {
  console.error("Resultado:         El descifrado tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}

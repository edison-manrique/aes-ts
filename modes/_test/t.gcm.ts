import { ModeOfOperationGCM } from "../gcm"

// La clave debe tener 16 bytes.
// El IV (Nonce) recomendado es de 12 bytes.
const key = new Uint8Array([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
const nonce = new Uint8Array([0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x02, 0x03, 0x04])

// Crea una instancia de la clase de modo GCM.
const gcm = new ModeOfOperationGCM(key, nonce)

// Cifrado
const plaintextString = "¡Este es un mensaje secreto!"
const associatedDataString = "AAD para GCM"
const plaintextBytes = new TextEncoder().encode(plaintextString)
const associatedData = new TextEncoder().encode(associatedDataString)

// Cifra los datos y genera una etiqueta.
const { ciphertext, tag } = gcm.encrypt(plaintextBytes, associatedData)

console.log(`Modo:              AES - ${gcm.description}`)
console.log(`Clave:             ${key.toHex()}`)
console.log(`Nonce:             ${nonce.toHex()}`)
console.log(`Texto Plano:       ${plaintextString}`)
console.log(`Datos Asociados:   ${associatedDataString}`)
console.log(`Texto Cifrado:     ${ciphertext.toBase64()}`)
console.log(`Etiqueta (Tag):    ${tag.toHex()}`)

// Descifrado
// Intenta descifrar. Si la autenticación falla, devolverá null.
const decryptedPlaintext = gcm.decrypt(ciphertext, tag, associatedData)

if (decryptedPlaintext) {
  const decryptedString = new TextDecoder().decode(decryptedPlaintext)
  console.log(`Descifrado:        ${decryptedString}`)
} else {
  console.error("¡Fallo de autenticación! El mensaje o los datos asociados fueron alterados.")
}
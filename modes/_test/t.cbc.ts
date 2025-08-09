import { ModeOfOperationCBC } from "../cbc"
import { pkcs7pad, pkcs7strip } from "../../padding"

// La clave y el IV (Vector de Inicialización) deben tener 16 bytes (128 bits) de longitud.
const key = new Uint8Array([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
const iv = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])

// Crea una instancia de la clase de modo CBC.
const cbc = new ModeOfOperationCBC(key, iv)

// Cifrado
const plaintextString = "¡Este es un mensaje secreto!" // "This is a secret message!"

// Convierte la cadena a un Uint8Array usando TextEncoder.
const plaintextBytes = new TextEncoder().encode(plaintextString)

// Añade relleno PKCS7 al texto plano.
const paddedPlaintext = pkcs7pad(plaintextBytes)

// Cifra los datos rellenados.
const ciphertext = cbc.encrypt(paddedPlaintext)

console.log(`Modo:          AES - ${cbc.description}`)
console.log(`Clave:         ${key.toHex()}`)
console.log(`IV:            ${iv.toHex()}`)
console.log(`Texto Plano:   ${plaintextString}`)
console.log(`Texto Cifrado: ${ciphertext.toBase64()}`)

// Descifrado
// Crea una nueva instancia para el descifrado (o reutiliza la existente, pero ten en cuenta su estado interno)
const cbcDecryptor = new ModeOfOperationCBC(key, iv)

// Descifra el texto cifrado.
const decryptedPaddedPlaintext = cbcDecryptor.decrypt(ciphertext)

// Elimina el relleno PKCS7 de los datos descifrados.
const decryptedPlaintextBytes = pkcs7strip(decryptedPaddedPlaintext)

// Convierte el Uint8Array de nuevo a una cadena.
const decryptedString = new TextDecoder().decode(decryptedPlaintextBytes)

console.log(`Descifrado:    ${decryptedString}`)

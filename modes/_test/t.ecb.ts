import { ModeOfOperationECB } from "../ecb"
import { pkcs7pad, pkcs7strip } from "../../padding"

// La clave debe tener 16, 24 o 32 bytes. Aquí usamos una de 16 bytes.
const key = new Uint8Array([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])

// Crea una instancia de la clase de modo ECB.
const ecb = new ModeOfOperationECB(key)

// Cifrado
const plaintextString = "¡Este es un mensaje secreto!"
// Convierte la cadena a un Uint8Array usando TextEncoder.
const plaintextBytes = new TextEncoder().encode(plaintextString)
// Añade relleno PKCS7 al texto plano para que su longitud sea un múltiplo de 16 bytes.
const paddedPlaintext = pkcs7pad(plaintextBytes)

// Cifra los datos rellenados.
const ciphertext = ecb.encrypt(paddedPlaintext)

console.log(`Modo:          AES - ${ecb.description}`)
console.log(`Clave:         ${key.toHex()}`)
console.log(`Texto Plano:   ${plaintextString}`)
console.log(`Texto Cifrado: ${ciphertext.toBase64()}`)

// Descifrado
// Crea una nueva instancia para el descifrado (no es necesario, ya que ECB es sin estado, pero se hace para seguir el ejemplo de CBC)
const ecbDecryptor = new ModeOfOperationECB(key)

// Descifra el texto cifrado.
const decryptedPaddedPlaintext = ecbDecryptor.decrypt(ciphertext)

// Elimina el relleno PKCS7 de los datos descifrados.
const decryptedPlaintextBytes = pkcs7strip(decryptedPaddedPlaintext)

// Convierte el Uint8Array de nuevo a una cadena.
const decryptedString = new TextDecoder().decode(decryptedPlaintextBytes)

console.log(`Descifrado:    ${decryptedString}`)

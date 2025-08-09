import { ModeOfOperationCFB } from "../cfb"
import { pkcs7pad, pkcs7strip } from "../../padding"

// La clave y el IV (Vector de Inicialización) deben tener 16 bytes de longitud.
const key = new Uint8Array([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
const iv = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])

// Define el tamaño del segmento para CFB.
// El texto plano debe ser un múltiplo de este tamaño.
const segmentSize = 8

// Crea una instancia de la clase de modo CFB con la clave, el IV y el tamaño del segmento.
const cfb = new ModeOfOperationCFB(key, iv, segmentSize)

// Cifrado
const plaintextString = "¡Este es un mensaje secreto!"

// El relleno no es estrictamente necesario si el texto plano es un múltiplo del tamaño del segmento.
// Sin embargo, para manejar cualquier longitud, primero se debe rellenar.
const plaintextBytes = new TextEncoder().encode(plaintextString)
const paddedPlaintext = pkcs7pad(plaintextBytes, segmentSize)

// Cifra los datos rellenados.
const ciphertext = cfb.encrypt(paddedPlaintext)

console.log(`Modo:          AES - ${cfb.description}`)
console.log(`Clave:         ${key.toHex()}`)
console.log(`IV:            ${iv.toHex()}`)
console.log(`Segment Size:  ${segmentSize} bytes`)
console.log(`Texto Plano:   ${plaintextString}`)
console.log(`Texto Cifrado: ${ciphertext.toBase64()}`)

// Descifrado
// Se necesita una nueva instancia del modo CFB con la misma clave, IV y tamaño de segmento.
const cfbDecryptor = new ModeOfOperationCFB(key, iv, segmentSize)

// Descifra el texto cifrado.
const decryptedPaddedPlaintext = cfbDecryptor.decrypt(ciphertext)

// Elimina el relleno PKCS7 de los datos descifrados.
const decryptedPlaintextBytes = pkcs7strip(decryptedPaddedPlaintext)

// Convierte el Uint8Array de nuevo a una cadena.
const decryptedString = new TextDecoder().decode(decryptedPlaintextBytes)

console.log(`Descifrado:    ${decryptedString}`)

import { ModeOfOperationOFB } from "../ofb"

// La clave y el IV (Vector de Inicialización) deben tener 16 bytes de longitud.
const key = new Uint8Array([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
const iv = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])

// Crea una instancia de la clase de modo OFB.
const ofb = new ModeOfOperationOFB(key, iv)

// Cifrado
const plaintextString = "¡Este es un mensaje secreto!"
// Convierte la cadena a un Uint8Array.
const plaintextBytes = new TextEncoder().encode(plaintextString)

// Cifra los datos. En OFB, al ser un cifrado de flujo, no se necesita relleno.
const ciphertext = ofb.encrypt(plaintextBytes)

console.log(`Modo:          AES - ${ofb.description}`)
console.log(`Clave:         ${key.toHex()}`)
console.log(`IV:            ${iv.toHex()}`)
console.log(`Texto Plano:   ${plaintextString}`)
console.log(`Texto Cifrado: ${ciphertext.toBase64()}`)

// Descifrado
// Se necesita una nueva instancia para el descifrado con la misma clave e IV.
// El modo OFB es simétrico para el cifrado y descifrado.
const ofbDecryptor = new ModeOfOperationOFB(key, iv)

// Descifra el texto cifrado.
const decryptedPlaintextBytes = ofbDecryptor.decrypt(ciphertext)

// Convierte el Uint8Array de nuevo a una cadena.
const decryptedString = new TextDecoder().decode(decryptedPlaintextBytes)

console.log(`Descifrado:    ${decryptedString}`)

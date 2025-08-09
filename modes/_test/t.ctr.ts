import { ModeOfOperationCTR, Counter } from "../ctr"

// La clave debe tener 16, 24 o 32 bytes. Aquí usamos una de 16 bytes.
const key = new Uint8Array([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])

// El contador se puede inicializar con un valor numérico o un Uint8Array de 16 bytes.
const initialCounter = new Counter(1)

// Crea una instancia de la clase de modo CTR.
// Es importante notar que el contador se modificará durante el cifrado y descifrado.
const ctr = new ModeOfOperationCTR(key, initialCounter)

// Cifrado
const plaintextString = "¡Este es un mensaje secreto!"
// En CTR no es necesario el relleno, ya que es un modo de flujo.
const plaintextBytes = new TextEncoder().encode(plaintextString)

// Cifra los datos.
const ciphertext = ctr.encrypt(plaintextBytes)

console.log(`Modo:          AES - ${ctr.description}`)
console.log(`Clave:         ${key.toHex()}`)
console.log(`Texto Plano:   ${plaintextString}`)
console.log(`Texto Cifrado: ${ciphertext.toBase64()}`)

// Descifrado
// Se necesita una nueva instancia del modo CTR con el mismo valor inicial del contador.
const ctrDecryptor = new ModeOfOperationCTR(key, 1)

// Descifra el texto cifrado.
const decryptedPlaintextBytes = ctrDecryptor.decrypt(ciphertext)

// Convierte el Uint8Array de nuevo a una cadena.
const decryptedString = new TextDecoder().decode(decryptedPlaintextBytes)

console.log(`Descifrado:    ${decryptedString}`)

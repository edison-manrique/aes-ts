// Importa la clase CCM corregida
import { ModeOfOperationCCM } from "../ccm"

// La clave debe tener 16, 24 o 32 bytes. Usamos 16 bytes (AES-128).
const key = new Uint8Array([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])

// Texto plano y datos asociados de ejemplo.
const plaintextString = "¡Este es un mensaje secreto!"

const associatedDataString = "AAD para CCM"

const plaintextBytes = new TextEncoder().encode(plaintextString)
const associatedData = new TextEncoder().encode(associatedDataString)

// Al llamar a new ModeOfOperationCCM(key), se usan los valores por defecto:
// tagSize = 16 y L = 4.
// La longitud del Nonce (IV) debe ser 15 - L.
// Con L = 4, la longitud del Nonce debe ser 15 - 4 = 11 bytes.
//
// Tu nonce original tenía 13 bytes, lo que corresponde a L = 2.
// Hemos ajustado el nonce a 11 bytes para que coincida con el L por defecto.
const iv = new Uint8Array([0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8])

// --- EJECUCIÓN ---

// Crea una instancia de la clase de modo CCM usando el L por defecto (4).
// Si quisieras usar un L=2 (y un nonce de 13 bytes), lo instanciarías así:
// const ccm = new ModeOfOperationCCM(key, 16, 2)
const ccm = new ModeOfOperationCCM(key, 16, 4)

console.log("--- CIFRADO ---")
console.log(`Modo:              AES - ${ccm.description}`)
console.log(`Clave:             ${key.toHex()}`)
console.log(`Nonce (IV):        ${iv.toHex()} (${iv.length} bytes)`)
console.log(`Texto Plano:       "${plaintextString}"`)
console.log(`Datos Asociados:   "${associatedDataString}"`)

// Cifra los datos y genera una etiqueta.
const { ciphertext, tag } = ccm.encrypt(plaintextBytes, iv, associatedData)

console.log(`Texto Cifrado:     ${ciphertext.toBase64()}`)
console.log(`Etiqueta (Tag):    ${tag.toHex()} (${tag.length} bytes)`)
console.log("\n--- DESCIFRADO ---")

// Intenta descifrar. Si la autenticación falla, devolverá null.
const decryptedPlaintext = ccm.decrypt(ciphertext, iv, tag, associatedData)

if (decryptedPlaintext) {
  const decryptedString = new TextDecoder().decode(decryptedPlaintext)
  console.log(`Estado:            ¡Éxito!`)
  console.log(`Texto Descifrado:  "${decryptedString}"`)

  // Verificación final
  if (plaintextString === decryptedString) {
    console.log("VERIFICACIÓN:      El texto descifrado coincide con el original. ¡Correcto!")
  } else {
    console.error("VERIFICACIÓN:     ¡ERROR! El texto descifrado no coincide.")
  }
} else {
  console.error("¡FALLO DE AUTENTICACIÓN! El mensaje, la etiqueta o los datos asociados fueron alterados.")
}

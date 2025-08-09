import { ModeOfOperationKWP } from "../kwp"

// --- Datos de Prueba ---
// KEK (Key-Encrypting Key) de 128 bits.
const keyEncryptingKey = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
// Clave de texto plano a envolver. Usaremos una longitud de 20 bytes (160 bits),
// que NO es múltiplo de 8, para probar la lógica de relleno.
const plaintextKeyToWrap = new Uint8Array([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23])

// Crea una instancia de la clase KWP con la KEK.
const kwp = new ModeOfOperationKWP(keyEncryptingKey)

console.log("--- Prueba de Envoltura y Desenvoltura AES-KWP ---")

// --- Envoltura (Wrap) ---
const wrappedKey = kwp.wrap(plaintextKeyToWrap)

console.log(`Modo:              ${kwp.description}`)
console.log(`KEK:               ${keyEncryptingKey.toHex()}`)
console.log(`Clave a Envolver (longitud ${plaintextKeyToWrap.length}):  ${plaintextKeyToWrap.toHex()}`)
console.log(`Clave Envuelta:    ${wrappedKey.toHex()}`)
console.log("\n")

// --- Desenvoltura (Unwrap - Caso de Éxito) ---
console.log("--- Intentando desenvolver con datos correctos ---")
const unwrappedKey = kwp.unwrap(wrappedKey)

if (unwrappedKey) {
  console.log(`Resultado:         Éxito`)
  console.log(`Clave Desenvuelta: ${unwrappedKey.toHex()}`)
  // Verificación final
  if (unwrappedKey.toHex() === plaintextKeyToWrap.toHex()) {
    console.log("VERIFICACIÓN:      La clave desenvuelta coincide con la original. ✅")
  } else {
    console.error("VERIFICACIÓN:      ¡ERROR! La clave desenvuelta NO coincide. ❌")
  }
} else {
  console.error("Resultado:         ¡Fallo de verificación de integridad inesperado! ❌")
}
console.log("\n")

// --- Prueba de Fallo de Integridad (Clave Envuelta Alterada) ---
console.log("--- Intentando desenvolver con CLAVE ENVUELTA ALTERADA ---")
const tamperedWrappedKey = new Uint8Array(wrappedKey)
tamperedWrappedKey[5] ^= 0xab // Alterar un byte de la clave envuelta.

const failedUnwrap1 = kwp.unwrap(tamperedWrappedKey)

if (failedUnwrap1 === null) {
  console.log("Resultado:         Fallo de integridad como se esperaba. ✅")
} else {
  console.error("Resultado:         La desenvoltura tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}
console.log("\n")

// --- Prueba de Fallo de Integridad (KEK Incorrecta) ---
console.log("--- Intentando desenvolver con KEK INCORRECTA ---")
const wrongKek = new Uint8Array(16).fill(0xaa) // Una clave KEK diferente.
const kwp_wrong = new ModeOfOperationKWP(wrongKek)

const failedUnwrap2 = kwp_wrong.unwrap(wrappedKey)

if (failedUnwrap2 === null) {
  console.log("Resultado:         Fallo de integridad como se esperaba. ✅")
} else {
  console.error("Resultado:         La desenvoltura tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}

import { ModeOfOperationKW } from "../kw"

// --- Datos de Prueba del RFC 3394 ---
// KEK (Key-Encrypting Key) de 128 bits.
const keyEncryptingKey = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
// Clave de texto plano a envolver (128 bits).
const plaintextKeyToWrap = new Uint8Array([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
// Resultado esperado oficial del RFC.
const expectedWrappedKeyHex = "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"

// Crea una instancia de la clase KW con la KEK.
const kw = new ModeOfOperationKW(keyEncryptingKey)

console.log("--- Prueba de Envoltura y Desenvoltura AES-KW ---")

// --- Envoltura (Wrap) ---
const wrappedKey = kw.wrap(plaintextKeyToWrap)

console.log(`Modo:              ${kw.description}`)
console.log(`KEK:               ${keyEncryptingKey.toHex()}`)
console.log(`Clave a Envolver:  ${plaintextKeyToWrap.toHex()}`)
console.log(`Clave Envuelta:    ${wrappedKey.toHex()}`)
console.log("\n")

// --- Verificación contra el Vector de Prueba Oficial ---
console.log("--- Verificando contra el vector de prueba del RFC ---")
if (wrappedKey.toHex() === expectedWrappedKeyHex) {
  console.log("VERIFICACIÓN:      La clave envuelta coincide con el vector oficial del RFC. ✅")
} else {
  console.error("VERIFICACIÓN:      ¡ERROR! La clave envuelta NO coincide con el estándar. ❌")
  console.error(`Esperado:          ${expectedWrappedKeyHex}`)
}
console.log("\n")

// --- Desenvoltura (Unwrap - Caso de Éxito) ---
console.log("--- Intentando desenvolver con datos correctos ---")
const unwrappedKey = kw.unwrap(wrappedKey)

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
tamperedWrappedKey[10] ^= 0xff // Alterar un byte en medio de la clave envuelta.

const failedUnwrap1 = kw.unwrap(tamperedWrappedKey)

if (failedUnwrap1 === null) {
  console.log("Resultado:         Fallo de integridad como se esperaba. ✅")
} else {
  console.error("Resultado:         La desenvoltura tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}
console.log("\n")

// --- Prueba de Fallo de Integridad (KEK Incorrecta) ---
console.log("--- Intentando desenvolver con KEK INCORRECTA ---")
const wrongKek = new Uint8Array(16) // Una clave KEK diferente (llena de ceros).
const kw_wrong = new ModeOfOperationKW(wrongKek)

const failedUnwrap2 = kw_wrong.unwrap(wrappedKey)

if (failedUnwrap2 === null) {
  console.log("Resultado:         Fallo de integridad como se esperaba. ✅")
} else {
  console.error("Resultado:         La desenvoltura tuvo éxito inesperadamente. ¡Vulnerabilidad potencial! ❌")
}

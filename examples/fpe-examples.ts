import { ModeOfOperationFPE_FF1 } from "../modes/fpe-ff1"

/**
 * FPE-FF1 Mode Examples
 * Demonstrating Format-Preserving Encryption capabilities
 */

// Utility function to create a test key
function createTestKey(length: number = 32): Uint8Array {
  const key = new Uint8Array(length)
  for (let i = 0; i < length; i++) {
    key[i] = (i * 3 + 7) % 256
  }
  return key
}

// Utility function to create test tweak
function createTestTweak(length: number = 8): Uint8Array {
  const tweak = new Uint8Array(length)
  for (let i = 0; i < length; i++) {
    tweak[i] = (i * 11 + 17) % 256
  }
  return tweak
}

// Example 1: Credit Card Number Encryption
function exampleCreditCard() {
  console.log("=== Credit Card Number Encryption ===")
  
  const key = createTestKey(32) // 256-bit key
  const alphabet = "0123456789" // Numeric alphabet
  const fpe = new ModeOfOperationFPE_FF1(key, alphabet)
  
  // Example credit card number (16 digits)
  const creditCard = "4532123456789012"
  const tweak = createTestTweak(8) // 8-byte tweak
  
  console.log("Original Credit Card:", creditCard)
  console.log("Tweak:", Array.from(tweak).map(b => b.toString(16).padStart(2, '0')).join(''))
  
  try {
    const encrypted = fpe.encrypt(creditCard, tweak)
    console.log("Encrypted Credit Card:", encrypted)
    
    const decrypted = fpe.decrypt(encrypted, tweak)
    console.log("Decrypted Credit Card:", decrypted)
    console.log("Match:", creditCard === decrypted)
    console.log("Format Preserved:", encrypted.length === creditCard.length && /^\d+$/.test(encrypted))
  } catch (error) {
    console.error("Credit Card FPE Error:", error)
  }
  
  console.log()
}

// Example 2: Alphanumeric Identifier Encryption
function exampleAlphanumeric() {
  console.log("=== Alphanumeric Identifier Encryption ===")
  
  const key = createTestKey(32) // 256-bit key
  const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" // Alphanumeric alphabet
  const fpe = new ModeOfOperationFPE_FF1(key, alphabet)
  
  // Example alphanumeric identifier
  const identifier = "A1B2C3D4E5"
  const tweak = createTestTweak(6) // 6-byte tweak
  
  console.log("Original Identifier:", identifier)
  console.log("Tweak:", Array.from(tweak).map(b => b.toString(16).padStart(2, '0')).join(''))
  
  try {
    const encrypted = fpe.encrypt(identifier, tweak)
    console.log("Encrypted Identifier:", encrypted)
    
    const decrypted = fpe.decrypt(encrypted, tweak)
    console.log("Decrypted Identifier:", decrypted)
    console.log("Match:", identifier === decrypted)
    console.log("Format Preserved:", encrypted.length === identifier.length && /^[0-9A-Z]+$/.test(encrypted))
  } catch (error) {
    console.error("Alphanumeric FPE Error:", error)
  }
  
  console.log()
}

// Example 3: Custom Alphabet Encryption
function exampleCustomAlphabet() {
  console.log("=== Custom Alphabet Encryption ===")
  
  const key = createTestKey(32) // 256-bit key
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Custom alphabet (Crockford's Base32)
  const fpe = new ModeOfOperationFPE_FF1(key, alphabet)
  
  // Example identifier using custom alphabet
  const identifier = "ABCDEFGHJK2345"
  const tweak = createTestTweak(4) // 4-byte tweak
  
  console.log("Original Identifier:", identifier)
  console.log("Alphabet:", alphabet)
  console.log("Tweak:", Array.from(tweak).map(b => b.toString(16).padStart(2, '0')).join(''))
  
  try {
    const encrypted = fpe.encrypt(identifier, tweak)
    console.log("Encrypted Identifier:", encrypted)
    
    const decrypted = fpe.decrypt(encrypted, tweak)
    console.log("Decrypted Identifier:", decrypted)
    console.log("Match:", identifier === decrypted)
    console.log("Format Preserved:", encrypted.length === identifier.length && 
                encrypted.split('').every(c => alphabet.includes(c)))
  } catch (error) {
    console.error("Custom Alphabet FPE Error:", error)
  }
  
  console.log()
}

// Example 4: Variable Length Encryption
function exampleVariableLength() {
  console.log("=== Variable Length Encryption ===")
  
  const key = createTestKey(32) // 256-bit key
  const alphabet = "0123456789" // Numeric alphabet
  const fpe = new ModeOfOperationFPE_FF1(key, alphabet)
  
  // Different length inputs (respecting minimum length of 6 for this alphabet)
  const inputs = ["123456", "1234567", "12345678", "123456789012"]
  const tweak = createTestTweak(8) // 8-byte tweak
  
  console.log("Tweak:", Array.from(tweak).map(b => b.toString(16).padStart(2, '0')).join(''))
  
  inputs.forEach((input, index) => {
    try {
      const encrypted = fpe.encrypt(input, tweak)
      const decrypted = fpe.decrypt(encrypted, tweak)
      console.log(`Input[${index}]: ${input} -> Encrypted: ${encrypted} -> Decrypted: ${decrypted} (Match: ${input === decrypted})`)
      console.log(`  Length Preserved: ${input.length === encrypted.length}`)
    } catch (error) {
      console.error(`Variable Length FPE Error for input[${index}]:`, error)
    }
  })
  
  console.log()
}

// Run all FPE examples
function runFPEExamples() {
  console.log("Starting FPE-FF1 mode examples...\n")
  
  exampleCreditCard()
  exampleAlphanumeric()
  exampleCustomAlphabet()
  exampleVariableLength()
  
  console.log("All FPE-FF1 examples completed!")
}

// Execute the examples
runFPEExamples()
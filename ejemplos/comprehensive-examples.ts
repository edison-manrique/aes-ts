import { HighLevelAES, AesMode } from "../high-level"

/**
 * Comprehensive examples demonstrating all AES modes with their specific properties
 */

// Utility function to create a test key
function createTestKey(length: number = 32): Uint8Array {
  const key = new Uint8Array(length)
  for (let i = 0; i < length; i++) {
    key[i] = (i * 3 + 7) % 256
  }
  return key
}

// Utility function to create test data
function createTestData(length: number = 32): Uint8Array {
  const data = new Uint8Array(length)
  for (let i = 0; i < length; i++) {
    data[i] = (i * 5 + 13) % 256
  }
  return data
}

// Utility function to create test IV/nonce
function createTestNonce(length: number = 16): Uint8Array {
  const nonce = new Uint8Array(length)
  for (let i = 0; i < length; i++) {
    nonce[i] = (i * 7 + 11) % 256
  }
  return nonce
}

// Utility function to create test tweak
function createTestTweak(length: number = 16): Uint8Array {
  const tweak = new Uint8Array(length)
  for (let i = 0; i < length; i++) {
    tweak[i] = (i * 11 + 17) % 256
  }
  return tweak
}

// Utility function to create associated authenticated data
function createTestAAD(): Uint8Array {
  return new TextEncoder().encode("This is associated authenticated data")
}

// Utility function to convert Uint8Array to hex string for display
function toHexString(bytes: Uint8Array): string {
  return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}

// Example 1: ECB Mode
function exampleECB() {
  console.log("=== ECB (Electronic Codebook) Mode ===")
  
  const key = createTestKey(32) // 256-bit key
  const aes = new HighLevelAES(AesMode.ECB, key)
  
  const plaintext = createTestData(32) // Multiple of block size
  console.log("Plaintext:", toHexString(plaintext))
  
  try {
    const encrypted = aes.encrypt(plaintext)
    console.log("Ciphertext:", toHexString(encrypted.ciphertext))
    
    const decrypted = aes.decrypt(encrypted.ciphertext)
    console.log("Decrypted:", toHexString(decrypted))
    console.log("Match:", plaintext.every((value, index) => value === decrypted[index]))
  } catch (error) {
    console.error("ECB Error:", error)
  }
  
  console.log()
}

// Example 2: CBC Mode
function exampleCBC() {
  console.log("=== CBC (Cipher Block Chaining) Mode ===")
  
  const key = createTestKey(32) // 256-bit key
  const iv = createTestNonce(16) // 128-bit IV
  const aes = new HighLevelAES(AesMode.CBC, key)
  
  const plaintext = createTestData(32) // Multiple of block size
  console.log("Plaintext:", toHexString(plaintext))
  console.log("IV:", toHexString(iv))
  
  try {
    const encrypted = aes.encrypt(plaintext, { iv })
    console.log("Ciphertext:", toHexString(encrypted.ciphertext))
    console.log("Used IV:", toHexString(encrypted.iv!))
    
    const decrypted = aes.decrypt(encrypted.ciphertext, { iv: encrypted.iv })
    console.log("Decrypted:", toHexString(decrypted))
    console.log("Match:", plaintext.every((value, index) => value === decrypted[index]))
  } catch (error) {
    console.error("CBC Error:", error)
  }
  
  console.log()
}

// Example 3: CTR Mode
function exampleCTR() {
  console.log("=== CTR (Counter) Mode ===")
  
  const key = createTestKey(32) // 256-bit key
  const nonce = createTestNonce(16) // 128-bit nonce
  const aes = new HighLevelAES(AesMode.CTR, key)
  
  const plaintext = createTestData(35) // Any length
  console.log("Plaintext:", toHexString(plaintext))
  console.log("Nonce:", toHexString(nonce))
  
  try {
    const encrypted = aes.encrypt(plaintext, { iv: nonce })
    console.log("Ciphertext:", toHexString(encrypted.ciphertext))
    console.log("Used Nonce:", toHexString(encrypted.iv!))
    
    const decrypted = aes.decrypt(encrypted.ciphertext, { iv: encrypted.iv })
    console.log("Decrypted:", toHexString(decrypted))
    console.log("Match:", plaintext.every((value, index) => value === decrypted[index]))
  } catch (error) {
    console.error("CTR Error:", error)
  }
  
  console.log()
}

// Example 4: CFB Mode
function exampleCFB() {
  console.log("=== CFB (Cipher Feedback) Mode ===")
  
  const key = createTestKey(32) // 256-bit key
  const iv = createTestNonce(16) // 128-bit IV
  const aes = new HighLevelAES(AesMode.CFB, key)
  
  const plaintext = createTestData(32) // Multiple of segment size
  console.log("Plaintext:", toHexString(plaintext))
  console.log("IV:", toHexString(iv))
  
  try {
    const encrypted = aes.encrypt(plaintext, { iv })
    console.log("Ciphertext:", toHexString(encrypted.ciphertext))
    console.log("Used IV:", toHexString(encrypted.iv!))
    
    const decrypted = aes.decrypt(encrypted.ciphertext, { iv: encrypted.iv })
    console.log("Decrypted:", toHexString(decrypted))
    console.log("Match:", plaintext.every((value, index) => value === decrypted[index]))
  } catch (error) {
    console.error("CFB Error:", error)
  }
  
  console.log()
}

// Example 5: OFB Mode
function exampleOFB() {
  console.log("=== OFB (Output Feedback) Mode ===")
  
  const key = createTestKey(32) // 256-bit key
  const iv = createTestNonce(16) // 128-bit IV
  const aes = new HighLevelAES(AesMode.OFB, key)
  
  const plaintext = createTestData(35) // Any length
  console.log("Plaintext:", toHexString(plaintext))
  console.log("IV:", toHexString(iv))
  
  try {
    const encrypted = aes.encrypt(plaintext, { iv })
    console.log("Ciphertext:", toHexString(encrypted.ciphertext))
    console.log("Used IV:", toHexString(encrypted.iv!))
    
    const decrypted = aes.decrypt(encrypted.ciphertext, { iv: encrypted.iv })
    console.log("Decrypted:", toHexString(decrypted))
    console.log("Match:", plaintext.every((value, index) => value === decrypted[index]))
  } catch (error) {
    console.error("OFB Error:", error)
  }
  
  console.log()
}

// Example 6: GCM Mode
function exampleGCM() {
  console.log("=== GCM (Galois/Counter Mode) ===")
  
  const key = createTestKey(32) // 256-bit key
  const iv = createTestNonce(12) // 96-bit IV (recommended for GCM)
  const aad = createTestAAD() // Associated authenticated data
  const aes = new HighLevelAES(AesMode.GCM, key)
  
  const plaintext = createTestData(35) // Any length
  console.log("Plaintext:", toHexString(plaintext))
  console.log("IV:", toHexString(iv))
  console.log("AAD:", new TextDecoder().decode(aad))
  
  try {
    const encrypted = aes.encrypt(plaintext, { iv, aad })
    console.log("Ciphertext:", toHexString(encrypted.ciphertext))
    console.log("Tag:", toHexString(encrypted.tag!))
    console.log("Used IV:", toHexString(encrypted.iv!))
    
    const decrypted = aes.decrypt(encrypted.ciphertext, { 
      iv: encrypted.iv, 
      tag: encrypted.tag, 
      aad 
    })
    console.log("Decrypted:", toHexString(decrypted))
    console.log("Match:", plaintext.every((value, index) => value === decrypted[index]))
  } catch (error) {
    console.error("GCM Error:", error)
  }
  
  console.log()
}

// Example 7: CCM Mode
function exampleCCM() {
  console.log("=== CCM (Counter with CBC-MAC) Mode ===")
  
  const key = createTestKey(16) // 128-bit key (recommended for CCM)
  const nonce = createTestNonce(11) // 11-byte nonce (15-L where L=4 by default)
  const aad = createTestAAD() // Associated authenticated data
  const aes = new HighLevelAES(AesMode.CCM, key, 12) // 12-byte tag
  
  const plaintext = createTestData(35) // Any length
  console.log("Plaintext:", toHexString(plaintext))
  console.log("Nonce:", toHexString(nonce))
  console.log("AAD:", new TextDecoder().decode(aad))
  
  try {
    const encrypted = aes.encrypt(plaintext, { nonce, aad })
    console.log("Ciphertext:", toHexString(encrypted.ciphertext))
    console.log("Tag:", toHexString(encrypted.tag!))
    console.log("Used Nonce:", toHexString(encrypted.iv!))
    
    const decrypted = aes.decrypt(encrypted.ciphertext, { 
      nonce: encrypted.iv, 
      tag: encrypted.tag, 
      aad 
    })
    console.log("Decrypted:", toHexString(decrypted!))
    console.log("Match:", plaintext.every((value, index) => value === decrypted![index]))
  } catch (error) {
    console.error("CCM Error:", error)
  }
  
  console.log()
}

// Example 8: EAX Mode
function exampleEAX() {
  console.log("=== EAX Mode ===")
  
  const key = createTestKey(32) // 256-bit key
  const nonce = createTestNonce(16) // Any length nonce
  const aad = createTestAAD() // Associated authenticated data
  const aes = new HighLevelAES(AesMode.EAX, key, 14) // 14-byte tag
  
  const plaintext = createTestData(35) // Any length
  console.log("Plaintext:", toHexString(plaintext))
  console.log("Nonce:", toHexString(nonce))
  console.log("AAD:", new TextDecoder().decode(aad))
  
  try {
    const encrypted = aes.encrypt(plaintext, { nonce, aad })
    console.log("Ciphertext:", toHexString(encrypted.ciphertext))
    console.log("Tag:", toHexString(encrypted.tag!))
    console.log("Used Nonce:", toHexString(encrypted.iv!))
    
    const decrypted = aes.decrypt(encrypted.ciphertext, { 
      nonce: encrypted.iv, 
      tag: encrypted.tag, 
      aad 
    })
    console.log("Decrypted:", toHexString(decrypted!))
    console.log("Match:", plaintext.every((value, index) => value === decrypted![index]))
  } catch (error) {
    console.error("EAX Error:", error)
  }
  
  console.log()
}

// Example 9: CWC Mode
function exampleCWC() {
  console.log("=== CWC (Carter-Wegman Counter) Mode ===")
  
  const key = createTestKey(32) // 256-bit key
  const iv = createTestNonce(12) // 12-byte IV (required by CWC)
  const aad = createTestAAD() // Associated authenticated data
  const aes = new HighLevelAES(AesMode.CWC, key)
  
  const plaintext = createTestData(35) // Any length
  console.log("Plaintext:", toHexString(plaintext))
  console.log("IV:", toHexString(iv))
  console.log("AAD:", new TextDecoder().decode(aad))
  
  try {
    const encrypted = aes.encrypt(plaintext, { iv, aad })
    console.log("Ciphertext:", toHexString(encrypted.ciphertext))
    console.log("Tag:", toHexString(encrypted.tag!))
    console.log("Used IV:", toHexString(encrypted.iv!))
    
    const decrypted = aes.decrypt(encrypted.ciphertext, { 
      iv: encrypted.iv, 
      tag: encrypted.tag, 
      aad 
    })
    console.log("Decrypted:", toHexString(decrypted!))
    console.log("Match:", plaintext.every((value, index) => value === decrypted![index]))
  } catch (error) {
    console.error("CWC Error:", error)
  }
  
  console.log()
}

// Example 10: GCM-SIV Mode
function exampleGCMSIV() {
  console.log("=== GCM-SIV (Galois/Counter Mode with Synthetic IV) Mode ===")
  
  const key = createTestKey(32) // 256-bit key
  const nonce = createTestNonce(12) // 96-bit nonce
  const aad = createTestAAD() // Associated authenticated data
  const aes = new HighLevelAES(AesMode.GCM_SIV, key)
  
  const plaintext = createTestData(35) // Any length
  console.log("Plaintext:", toHexString(plaintext))
  console.log("Nonce:", toHexString(nonce))
  console.log("AAD:", new TextDecoder().decode(aad))
  
  try {
    const encrypted = aes.encrypt(plaintext, { nonce, aad })
    console.log("Ciphertext:", toHexString(encrypted.ciphertext))
    console.log("Tag:", toHexString(encrypted.tag!))
    console.log("Used Nonce:", toHexString(encrypted.iv!))
    
    const decrypted = aes.decrypt(encrypted.ciphertext, { 
      nonce: encrypted.iv, 
      tag: encrypted.tag, 
      aad 
    })
    console.log("Decrypted:", toHexString(decrypted!))
    console.log("Match:", plaintext.every((value, index) => value === decrypted![index]))
  } catch (error) {
    console.error("GCM-SIV Error:", error)
  }
  
  console.log()
}

// Example 11: OCB Mode
function exampleOCB() {
  console.log("=== OCB (Offset Codebook) Mode ===")
  
  const key = createTestKey(32) // 256-bit key
  const nonce = createTestNonce(12) // Any length nonce (12 bytes recommended)
  const aad = createTestAAD() // Associated authenticated data
  const aes = new HighLevelAES(AesMode.OCB, key, 13) // 13-byte tag
  
  const plaintext = createTestData(35) // Any length
  console.log("Plaintext:", toHexString(plaintext))
  console.log("Nonce:", toHexString(nonce))
  console.log("AAD:", new TextDecoder().decode(aad))
  
  try {
    const encrypted = aes.encrypt(plaintext, { nonce, aad })
    console.log("Ciphertext:", toHexString(encrypted.ciphertext))
    console.log("Tag:", toHexString(encrypted.tag!))
    console.log("Used Nonce:", toHexString(encrypted.iv!))
    
    const decrypted = aes.decrypt(encrypted.ciphertext, { 
      nonce: encrypted.iv, 
      tag: encrypted.tag, 
      aad 
    })
    console.log("Decrypted:", toHexString(decrypted!))
    console.log("Match:", plaintext.every((value, index) => value === decrypted![index]))
  } catch (error) {
    console.error("OCB Error:", error)
  }
  
  console.log()
}

// Example 12: XTS Mode
function exampleXTS() {
  console.log("=== XTS (XEX-based tweaked-codebook mode with ciphertext stealing) Mode ===")
  
  const key = createTestKey(64) // 512-bit key (two 256-bit keys)
  const tweak = createTestTweak(16) // 128-bit tweak
  const aes = new HighLevelAES(AesMode.XTS, key)
  
  const plaintext = createTestData(35) // At least 16 bytes
  console.log("Plaintext:", toHexString(plaintext))
  console.log("Tweak:", toHexString(tweak))
  
  try {
    const encrypted = aes.encrypt(plaintext, { tweak })
    console.log("Ciphertext:", toHexString(encrypted.ciphertext))
    
    const decrypted = aes.decrypt(encrypted.ciphertext, { tweak })
    console.log("Decrypted:", toHexString(decrypted))
    console.log("Match:", plaintext.every((value, index) => value === decrypted[index]))
  } catch (error) {
    console.error("XTS Error:", error)
  }
  
  console.log()
}

// Example 13: KW Mode
function exampleKW() {
  console.log("=== KW (Key Wrap) Mode ===")
  
  const key = createTestKey(32) // 256-bit key
  const aes = new HighLevelAES(AesMode.KW, key)
  
  // KW requires plaintext to be a multiple of 8 bytes
  const plaintext = createTestData(32) // Multiple of 8 bytes
  console.log("Plaintext:", toHexString(plaintext))
  
  try {
    const encrypted = aes.encrypt(plaintext)
    console.log("Ciphertext:", toHexString(encrypted.ciphertext))
    
    const decrypted = aes.decrypt(encrypted.ciphertext)
    console.log("Decrypted:", toHexString(decrypted!))
    console.log("Match:", plaintext.every((value, index) => value === decrypted![index]))
  } catch (error) {
    console.error("KW Error:", error)
  }
  
  console.log()
}

// Example 14: KWP Mode
function exampleKWP() {
  console.log("=== KWP (Key Wrap with Padding) Mode ===")
  
  const key = createTestKey(32) // 256-bit key
  const aes = new HighLevelAES(AesMode.KWP, key)
  
  // KWP can handle any length plaintext
  const plaintext = createTestData(35) // Any length
  console.log("Plaintext:", toHexString(plaintext))
  
  try {
    const encrypted = aes.encrypt(plaintext)
    console.log("Ciphertext:", toHexString(encrypted.ciphertext))
    
    const decrypted = aes.decrypt(encrypted.ciphertext)
    console.log("Decrypted:", toHexString(decrypted!))
    console.log("Match:", plaintext.every((value, index) => value === decrypted![index]))
  } catch (error) {
    console.error("KWP Error:", error)
  }
  
  console.log()
}

// Example 15: FPE-FF1 Mode
function exampleFPE_FF1() {
  console.log("=== FPE-FF1 (Format-Preserving Encryption) Mode ===")
  
  const key = createTestKey(32) // 256-bit key
  const aes = new HighLevelAES(AesMode.FPE_FF1, key)
  
  // FPE-FF1 works with text and requires an alphabet
  const plaintext = "1234567890123456" // 16-digit number
  const alphabet = "0123456789" // Numeric alphabet
  const tweak = createTestTweak(8) // Tweak for FPE
  console.log("Plaintext:", plaintext)
  console.log("Alphabet:", alphabet)
  console.log("Tweak:", toHexString(tweak))
  
  try {
    // FPE-FF1 requires special methods that accept an alphabet
    const encrypted = aes.encryptTextWithAlphabet(plaintext, alphabet, { tweak })
    console.log("Ciphertext:", encrypted)
    
    const decrypted = aes.decryptTextWithAlphabet(encrypted, alphabet, { tweak })
    console.log("Decrypted:", decrypted)
    console.log("Match:", plaintext === decrypted)
  } catch (error) {
    console.error("FPE-FF1 Error:", error)
  }
  
  // Another example with alphanumeric alphabet
  console.log("\n--- Alphanumeric Example ---")
  const alphaPlaintext = "A1B2C3D4E5F6"
  const alphaAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  console.log("Plaintext:", alphaPlaintext)
  console.log("Alphabet:", alphaAlphabet)
  
  try {
    const encrypted = aes.encryptTextWithAlphabet(alphaPlaintext, alphaAlphabet, { tweak })
    console.log("Ciphertext:", encrypted)
    
    const decrypted = aes.decryptTextWithAlphabet(encrypted, alphaAlphabet, { tweak })
    console.log("Decrypted:", decrypted)
    console.log("Match:", alphaPlaintext === decrypted)
  } catch (error) {
    console.error("FPE-FF1 Alphanumeric Error:", error)
  }
  
  console.log()
}

// Example 16: CBC-MAC Mode
function exampleCBC_MAC() {
  console.log("=== CBC-MAC (Cipher Block Chaining Message Authentication Code) Mode ===")
  
  const key = createTestKey(32) // 256-bit key
  const aes = new HighLevelAES(AesMode.CBC_MAC, key)
  
  const plaintext = createTestData(32) // Multiple of block size
  console.log("Plaintext:", toHexString(plaintext))
  
  try {
    const result = aes.encrypt(plaintext, { })
    console.log("MAC Tag:", toHexString(result.tag!))
    
    // Verify that CBC-MAC doesn't support decryption
    try {
      aes.decrypt(plaintext, { tag: result.tag })
      console.log("Unexpected: CBC-MAC should not support decryption")
    } catch (error) {
      console.log("Expected error:", (error as Error).message)
    }
  } catch (error) {
    console.error("CBC-MAC Error:", error)
  }
  
  console.log()
}

// Example 17: PMAC-SIV Mode
function examplePMAC_SIV() {
  console.log("=== PMAC-SIV (Parallelizable MAC with Synthetic IV) Mode ===")
  
  const key = createTestKey(16) // 128-bit key (as in the test)
  const nonce = createTestNonce(12) // 12-byte nonce (as in the test)
  const aad = createTestAAD() // Associated authenticated data
  const aes = new HighLevelAES(AesMode.PMAC_SIV, key, 16) // 16-byte tag (as in the test)
  
  const plaintext = createTestData(35) // Any length
  console.log("Plaintext:", toHexString(plaintext))
  console.log("Nonce:", toHexString(nonce))
  console.log("AAD:", new TextDecoder().decode(aad))
  
  try {
    const encrypted = aes.encrypt(plaintext, { nonce, aad })
    console.log("Ciphertext:", toHexString(encrypted.ciphertext))
    console.log("Tag:", toHexString(encrypted.tag!))
    console.log("Used Nonce:", toHexString(encrypted.iv!))
    
    const decrypted = aes.decrypt(encrypted.ciphertext, { 
      nonce: encrypted.iv, 
      tag: encrypted.tag, 
      aad 
    })
    console.log("Decrypted:", toHexString(decrypted!))
    console.log("Match:", plaintext.every((value, index) => value === decrypted![index]))
  } catch (error) {
    console.error("PMAC-SIV Error:", error)
  }
  
  console.log()
}

// Example 18: TKW Mode
function exampleTKW() {
  console.log("=== TKW (Tweakable Key Wrap) Mode ===")
  
  const key = createTestKey(32) // 256-bit key
  const tweak = createTestTweak(8) // Tweak for TKW
  const aes = new HighLevelAES(AesMode.TKW, key)
  
  // TKW can handle any length plaintext
  const plaintext = createTestData(35) // Any length
  console.log("Plaintext:", toHexString(plaintext))
  console.log("Tweak:", toHexString(tweak))
  
  try {
    const encrypted = aes.encrypt(plaintext, { tweak })
    console.log("Ciphertext:", toHexString(encrypted.ciphertext))
    
    const decrypted = aes.decrypt(encrypted.ciphertext, { tweak })
    console.log("Decrypted:", toHexString(decrypted!))
    console.log("Match:", plaintext.every((value, index) => value === decrypted![index]))
  } catch (error) {
    console.error("TKW Error:", error)
  }
  
  console.log()
}

// Example 19: HybridCTR Mode
function exampleHybridCTR() {
  console.log("=== HybridCTR (Hybrid Counter Mode with Authentication and Tweak) Mode ===")
  
  const key = createTestKey(32) // 256-bit key
  const nonce = createTestNonce(16) // 16-byte nonce
  const tweak = createTestTweak(16) // 16-byte tweak
  const aad = createTestAAD() // Associated authenticated data
  const aes = new HighLevelAES(AesMode.HYBRID_CTR, key, 16) // 16-byte tag
  
  const plaintext = createTestData(35) // Any length
  console.log("Plaintext:", toHexString(plaintext))
  console.log("Nonce:", toHexString(nonce))
  console.log("Tweak:", toHexString(tweak))
  console.log("AAD:", new TextDecoder().decode(aad))
  
  try {
    const encrypted = aes.encrypt(plaintext, { nonce, aad, tweak })
    console.log("Ciphertext:", toHexString(encrypted.ciphertext))
    console.log("Tag:", toHexString(encrypted.tag!))
    console.log("Used Nonce:", toHexString(encrypted.iv!))
    
    const decrypted = aes.decrypt(encrypted.ciphertext, { 
      nonce: encrypted.iv, 
      tag: encrypted.tag, 
      aad,
      tweak
    })
    console.log("Decrypted:", toHexString(decrypted!))
    console.log("Match:", plaintext.every((value, index) => value === decrypted![index]))
  } catch (error) {
    console.error("HybridCTR Error:", error)
  }
  
  console.log()
  
  // Example with synthetic nonce generation
  console.log("--- Example with Synthetic Nonce Generation ---")
  try {
    const encrypted2 = aes.encrypt(plaintext, { aad, tweak })
    console.log("Ciphertext:", toHexString(encrypted2.ciphertext))
    console.log("Tag:", toHexString(encrypted2.tag!))
    console.log("Synthetic Nonce:", toHexString(encrypted2.iv!))
    
    const decrypted2 = aes.decrypt(encrypted2.ciphertext, { 
      nonce: encrypted2.iv, 
      tag: encrypted2.tag, 
      aad,
      tweak
    })
    console.log("Decrypted:", toHexString(decrypted2!))
    console.log("Match:", plaintext.every((value, index) => value === decrypted2![index]))
  } catch (error) {
    console.error("HybridCTR Synthetic Nonce Error:", error)
  }
  
  console.log()
}

// Run all examples
function runAllExamples() {
  console.log("Starting comprehensive AES mode examples...\n")
  
  exampleECB()
  exampleCBC()
  exampleCTR()
  exampleCFB()
  exampleOFB()
  exampleGCM()
  exampleCCM()
  exampleEAX()
  exampleCWC()
  exampleGCMSIV()
  exampleOCB()
  exampleXTS()
  exampleKW()
  exampleKWP()
  exampleFPE_FF1()
  exampleCBC_MAC()
  examplePMAC_SIV()
  exampleTKW()
  exampleHybridCTR()
  
  console.log("All examples completed!")
}

// Execute the examples
runAllExamples()
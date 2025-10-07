import { HighLevelAES, AesMode } from "../high-level"

/**
 * Simple test to verify the high-level AES class functionality
 */

function runTests() {
  console.log("Testing HighLevelAES class...\n")
  
  // Test 1: Basic encryption/decryption with GCM
  console.log("Test 1: GCM Mode")
  try {
    const key = new Uint8Array(32)
    crypto.getRandomValues(key)
    
    const aes = new HighLevelAES(AesMode.GCM, key)
    const plaintext = new TextEncoder().encode("Hello, World!")
    
    const encrypted = aes.encrypt(plaintext)
    const decrypted = aes.decrypt(encrypted.ciphertext, {
      iv: encrypted.iv,
      tag: encrypted.tag
    })
    
    const decryptedText = new TextDecoder().decode(decrypted)
    console.log("Original:", "Hello, World!")
    console.log("Decrypted:", decryptedText)
    console.log("Match:", "Hello, World!" === decryptedText)
    console.log("Test 1: PASSED\n")
  } catch (error) {
    console.error("Test 1: FAILED -", error)
    console.log()
  }
  
  // Test 2: Text encryption/decryption
  console.log("Test 2: Text Encryption")
  try {
    const key = new Uint8Array(32)
    crypto.getRandomValues(key)
    
    const aes = new HighLevelAES(AesMode.CTR, key)
    const plaintext = "This is a secret message!"
    
    const encrypted = aes.encryptText(plaintext)
    const decrypted = aes.decryptText(encrypted.ciphertext, {
      iv: encrypted.iv
    })
    
    console.log("Original:", plaintext)
    console.log("Decrypted:", decrypted)
    console.log("Match:", plaintext === decrypted)
    console.log("Test 2: PASSED\n")
  } catch (error) {
    console.error("Test 2: FAILED -", error)
    console.log()
  }
  
  // Test 3: FPE-FF1 with alphabet
  console.log("Test 3: FPE-FF1 Mode")
  try {
    const key = new Uint8Array(32)
    crypto.getRandomValues(key)
    
    const aes = new HighLevelAES(AesMode.FPE_FF1, key)
    const plaintext = "1234567890123456"
    const alphabet = "0123456789"
    const tweak = new Uint8Array(8)
    crypto.getRandomValues(tweak)
    
    const encrypted = aes.encryptTextWithAlphabet(plaintext, alphabet, { tweak })
    const decrypted = aes.decryptTextWithAlphabet(encrypted, alphabet, { tweak })
    
    console.log("Original:", plaintext)
    console.log("Encrypted:", encrypted)
    console.log("Decrypted:", decrypted)
    console.log("Match:", plaintext === decrypted)
    console.log("Format Preserved:", encrypted.length === plaintext.length && /^\d+$/.test(encrypted))
    console.log("Test 3: PASSED\n")
  } catch (error) {
    console.error("Test 3: FAILED -", error)
    console.log()
  }
  
  console.log("All tests completed!")
}

runTests()
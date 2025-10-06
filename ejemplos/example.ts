import { HighLevelAES, AesMode } from "../high-level"

/**
 * Example demonstrating how to use the HighLevelAES class
 */

// Example 1: Simple text encryption with GCM mode
function exampleTextEncryption() {
  console.log("=== Text Encryption Example ===")
  
  // Create a 256-bit key
  const key = new Uint8Array(32)
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(key)
  } else {
    // Simple fallback for demo purposes
    for (let i = 0; i < key.length; i++) {
      key[i] = i * 3 % 256
    }
  }
  
  // Create AES-GCM instance
  const aes = new HighLevelAES(AesMode.GCM, key)
  
  // Encrypt text
  const plaintext = "Hello, this is a secret message!"
  const encrypted = aes.encryptText(plaintext)
  console.log("Original text:", plaintext)
  console.log("Encrypted text:", encrypted.ciphertext)
  console.log("IV:", encrypted.iv)
  console.log("Tag:", encrypted.tag)
  
  // Decrypt text
  const decrypted = aes.decryptText(encrypted.ciphertext, {
    iv: encrypted.iv,
    tag: encrypted.tag
  })
  console.log("Decrypted text:", decrypted)
  console.log("Match:", plaintext === decrypted)
  console.log()
}

// Example 2: Binary data encryption with CBC mode
function exampleBinaryEncryption() {
  console.log("=== Binary Data Encryption Example ===")
  
  // Create a 128-bit key
  const key = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
  
  // Create AES-CBC instance
  const aes = new HighLevelAES(AesMode.CBC, key)
  
  // Create some binary data
  const binaryData = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80, 90, 100])
  console.log("Original data:", binaryData)
  
  // Encrypt binary data
  const encrypted = aes.encrypt(binaryData)
  console.log("Encrypted data:", encrypted.ciphertext)
  console.log("IV:", encrypted.iv)
  
  // Decrypt binary data
  const decrypted = aes.decrypt(encrypted.ciphertext, {
    iv: encrypted.iv
  })
  console.log("Decrypted data:", decrypted)
  console.log("Match:", binaryData.every((value, index) => value === decrypted[index]))
  console.log()
}

// Example 3: File encryption simulation with CTR mode
function exampleFileEncryption() {
  console.log("=== File Encryption Example ===")
  
  // Create a 192-bit key
  const key = new Uint8Array(24)
  for (let i = 0; i < key.length; i++) {
    key[i] = (i * 7) % 256
  }
  
  // Create AES-CTR instance
  const aes = new HighLevelAES(AesMode.CTR, key)
  
  // Simulate file data
  const fileData = new TextEncoder().encode("This is file content that we want to encrypt securely")
  console.log("Original file content:", new TextDecoder().decode(fileData))
  
  // Encrypt file data
  const encryptedFile = aes.encryptFile(fileData)
  console.log("Encrypted file data:", encryptedFile.ciphertext)
  console.log("IV:", encryptedFile.iv)
  
  // Decrypt file data
  const decryptedFile = aes.decryptFile(encryptedFile.ciphertext, {
    iv: encryptedFile.iv
  })
  console.log("Decrypted file content:", new TextDecoder().decode(decryptedFile))
  console.log()
}

// Run examples
exampleTextEncryption()
exampleBinaryEncryption()
exampleFileEncryption()

console.log("=== All examples completed ===")
import { AES } from "./aes"
import { ModeOfOperationECB } from "./modes/ecb"
import { ModeOfOperationCBC } from "./modes/cbc"
import { ModeOfOperationCTR } from "./modes/ctr"
import { ModeOfOperationCFB } from "./modes/cfb"
import { ModeOfOperationOFB } from "./modes/ofb"
import { ModeOfOperationGCM } from "./modes/gcm"
import { ModeOfOperationCCM } from "./modes/ccm"
import { ModeOfOperationEAX } from "./modes/eax"
import { ModeOfOperationCWC } from "./modes/cwc"
import { ModeOfOperationGCM_SIV } from "./modes/gcm-siv"
import { ModeOfOperationOCB } from "./modes/ocb"
import { ModeOfOperationXTS } from "./modes/xts"
import { ModeOfOperationKW } from "./modes/kw"
import { ModeOfOperationKWP } from "./modes/kwp"
import { ModeOfOperationFPE_FF1 } from "./modes/fpe-ff1"
import { ModeOfOperationCBC_MAC } from "./modes/cbc-mac"
import { ModeOfOperationPMAC_SIV } from "./modes/pmac-siv"
import { ModeOfOperationTKW } from "./modes/tkw"

import { ModeOfOperationHybridCTR } from "./modes/hybrid-ctr"

/**
 * Enumeración que representa los diferentes modos de operación AES disponibles.
 */
export enum AesMode {
  ECB = "ecb",
  CBC = "cbc",
  CTR = "ctr",
  CFB = "cfb",
  OFB = "ofb",
  GCM = "gcm",
  CCM = "ccm",
  EAX = "eax",
  CWC = "cwc",
  GCM_SIV = "gcm-siv",
  OCB = "ocb",
  XTS = "xts",
  KW = "kw",
  KWP = "kwp",
  FPE_FF1 = "fpe-ff1",
  CBC_MAC = "cbc-mac",
  PMAC_SIV = "pmac-siv",
  TKW = "tkw",
  HYBRID_CTR = "hybrid-ctr"
}

/**
 * Interfaz para el resultado de cifrado que incluye el texto cifrado y la etiqueta de autenticación opcional.
 */
export interface EncryptionResult {
  ciphertext: Uint8Array
  tag?: Uint8Array
  iv?: Uint8Array
}

/**
 * Interfaz para el resultado de cifrado de texto.
 */
export interface TextEncryptionResult {
  ciphertext: string
  tag?: Uint8Array
  iv?: Uint8Array
}

/**
 * Clase de cifrado AES de alto nivel que proporciona una interfaz unificada para todos los modos AES.
 * Esta clase simplifica el uso de diferentes modos AES para varias tareas de cifrado
 * incluyendo texto, archivos y datos binarios.
 * 
 * Características principales:
 * - Interfaz unificada para todos los modos de operación AES
 * - Soporte para cifrado de texto, archivos y datos binarios
 * - Manejo automático de inicialización de vectores (IV)
 * - Soporte para datos asociados adicionales (AAD)
 * - Generación automática de nonces cuando no se proporcionan
 * 
 * @example
 * ```typescript
 * // Crear una instancia para AES-256-GCM
 * const aes = new HighLevelAES(AesMode.GCM, new Uint8Array(32));
 * 
 * // Cifrar texto
 * const encrypted = aes.encryptText("Hola, mundo!");
 * const decrypted = aes.decryptText(encrypted.ciphertext, { 
 *   iv: encrypted.iv!, 
 *   tag: encrypted.tag! 
 * });
 * 
 * // Cifrar datos binarios
 * const data = new Uint8Array([1, 2, 3, 4]);
 * const encryptedData = aes.encrypt(data);
 * const decryptedData = aes.decrypt(encryptedData.ciphertext, { 
 *   iv: encryptedData.iv, 
 *   tag: encryptedData.tag 
 * });
 * ```
 */
export class HighLevelAES {
  private readonly mode: AesMode
  private readonly key: Uint8Array
  private readonly tagSize?: number

  /**
   * Crea una nueva instancia de HighLevelAES.
   * @param mode El modo de operación AES a utilizar
   * @param key La clave de cifrado (debe ser de 16, 24 o 32 bytes para la mayoría de los modos, 32 o 64 bytes para XTS)
   * @param tagSize El tamaño de la etiqueta de autenticación (para modos autenticados)
   */
  constructor(mode: AesMode, key: Uint8Array, tagSize?: number) {
    // XTS mode requires special key length handling (32 or 64 bytes)
    if (mode === AesMode.XTS) {
      if (![32, 64].includes(key.length)) {
        throw new Error("Key for XTS mode must be 32 or 64 bytes long")
      }
    } else if (![16, 24, 32].includes(key.length)) {
      throw new Error("Key must be 16, 24, or 32 bytes long")
    }
    
    this.mode = mode
    this.key = key
    this.tagSize = tagSize
  }

  /**
   * Cifra datos binarios.
   * @param plaintext Los datos a cifrar
   * @param options Opciones adicionales como IV, AAD, etc.
   * @returns Resultado de cifrado con texto cifrado y posiblemente etiqueta/iv
   */
  public encrypt(plaintext: Uint8Array, options?: {
    iv?: Uint8Array,
    aad?: Uint8Array,
    nonce?: Uint8Array,
    tweak?: Uint8Array
  }): EncryptionResult {
    switch (this.mode) {
      case AesMode.ECB:
        return this.encryptECB(plaintext)
      
      case AesMode.CBC:
        return this.encryptCBC(plaintext, options?.iv)
      
      case AesMode.CTR:
        return this.encryptCTR(plaintext, options?.iv)
      
      case AesMode.CFB:
        return this.encryptCFB(plaintext, options?.iv)
      
      case AesMode.OFB:
        return this.encryptOFB(plaintext, options?.iv)
      
      case AesMode.GCM:
        return this.encryptGCM(plaintext, options?.iv, options?.aad)
      
      case AesMode.CCM:
        return this.encryptCCM(plaintext, options?.nonce || options?.iv, options?.aad)
      
      case AesMode.EAX:
        return this.encryptEAX(plaintext, options?.nonce || options?.iv, options?.aad)
      
      case AesMode.CWC:
        return this.encryptCWC(plaintext, options?.iv, options?.aad)
      
      case AesMode.GCM_SIV:
        return this.encryptGCM_SIV(plaintext, options?.nonce || options?.iv, options?.aad)
      
      case AesMode.OCB:
        return this.encryptOCB(plaintext, options?.nonce || options?.iv, options?.aad)
      
      case AesMode.XTS:
        if (!options?.tweak) {
          throw new Error("XTS mode requires a tweak")
        }
        return this.encryptXTS(plaintext, options.tweak)
      
      case AesMode.KW:
        return this.encryptKW(plaintext)
      
      case AesMode.KWP:
        return this.encryptKWP(plaintext)
      
      case AesMode.CBC_MAC:
        return this.generateCBC_MAC(plaintext, this.tagSize)
      
      case AesMode.PMAC_SIV:
        return this.encryptPMAC_SIV(plaintext, options?.nonce || options?.iv, options?.aad)
      
      case AesMode.TKW:
        if (!options?.tweak) {
          throw new Error("TKW mode requires a tweak")
        }
        return this.encryptTKW(plaintext, options.tweak)
      
      case AesMode.HYBRID_CTR:
        return this.encryptHybridCTR(plaintext, options?.nonce || options?.iv, options?.aad, options?.tweak)
      
      default:
        throw new Error(`Encryption not implemented for mode: ${this.mode}`)
    }
  }

  /**
   * Descifra datos binarios.
   * @param ciphertext Los datos a descifrar
   * @param options Opciones adicionales como IV, etiqueta, AAD, etc.
   * @returns Texto plano descifrado
   */
  public decrypt(ciphertext: Uint8Array, options?: {
    iv?: Uint8Array,
    tag?: Uint8Array,
    aad?: Uint8Array,
    nonce?: Uint8Array,
    tweak?: Uint8Array
  }): Uint8Array {
    switch (this.mode) {
      case AesMode.ECB:
        return this.decryptECB(ciphertext)
      
      case AesMode.CBC:
        return this.decryptCBC(ciphertext, options?.iv)
      
      case AesMode.CTR:
        return this.decryptCTR(ciphertext, options?.iv)
      
      case AesMode.CFB:
        return this.decryptCFB(ciphertext, options?.iv)
      
      case AesMode.OFB:
        return this.decryptOFB(ciphertext, options?.iv)
      
      case AesMode.GCM:
        if (!options?.tag) {
          throw new Error("GCM mode requires an authentication tag")
        }
        return this.decryptGCM(ciphertext, options.tag, options.iv, options?.aad) || 
               this.handleDecryptionFailure("GCM authentication failed")
      
      case AesMode.CCM:
        if (!options?.tag) {
          throw new Error("CCM mode requires an authentication tag")
        }
        return this.decryptCCM(ciphertext, options.tag, options.nonce || options.iv, options?.aad) || 
               this.handleDecryptionFailure("CCM authentication failed")
      
      case AesMode.EAX:
        if (!options?.tag) {
          throw new Error("EAX mode requires an authentication tag")
        }
        return this.decryptEAX(ciphertext, options.tag, options.nonce || options.iv, options?.aad) || 
               this.handleDecryptionFailure("EAX authentication failed")
      
      case AesMode.CWC:
        if (!options?.tag) {
          throw new Error("CWC mode requires an authentication tag")
        }
        return this.decryptCWC(ciphertext, options.tag, options.iv, options?.aad) || 
               this.handleDecryptionFailure("CWC authentication failed")
      
      case AesMode.GCM_SIV:
        if (!options?.tag) {
          throw new Error("GCM-SIV mode requires an authentication tag")
        }
        return this.decryptGCM_SIV(ciphertext, options.tag, options.nonce || options.iv, options?.aad) || 
               this.handleDecryptionFailure("GCM-SIV authentication failed")
      
      case AesMode.OCB:
        if (!options?.tag) {
          throw new Error("OCB mode requires an authentication tag")
        }
        return this.decryptOCB(ciphertext, options.tag, options.nonce || options.iv, options?.aad) || 
               this.handleDecryptionFailure("OCB authentication failed")
      
      case AesMode.XTS:
        if (!options?.tweak) {
          throw new Error("XTS mode requires a tweak")
        }
        return this.decryptXTS(ciphertext, options.tweak)
      
      case AesMode.KW:
        return this.decryptKW(ciphertext) || 
               this.handleDecryptionFailure("KW decryption failed")
      
      case AesMode.KWP:
        return this.decryptKWP(ciphertext) || 
               this.handleDecryptionFailure("KWP decryption failed")
      
      case AesMode.CBC_MAC:
        throw new Error("CBC-MAC is a MAC-only mode and does not support decryption")
      
      case AesMode.PMAC_SIV:
        if (!options?.tag) {
          throw new Error("PMAC-SIV mode requires an authentication tag")
        }
        const pmacSivResult = this.decryptPMAC_SIV(ciphertext, options.tag, options.nonce || options.iv, options?.aad)
        if (pmacSivResult === null) {
          return this.handleDecryptionFailure("PMAC-SIV authentication failed")
        }
        return pmacSivResult
      
      case AesMode.TKW:
        if (!options?.tweak) {
          throw new Error("TKW mode requires a tweak")
        }
        const tkwResult = this.decryptTKW(ciphertext, options.tweak)
        if (tkwResult === null) {
          return this.handleDecryptionFailure("TKW decryption failed")
        }
        return tkwResult
      
      case AesMode.HYBRID_CTR:
        if (!options?.tag) {
          throw new Error("HybridCTR mode requires an authentication tag")
        }
        if (!options?.nonce) {
          throw new Error("HybridCTR mode requires a nonce")
        }
        const hybridCtrResult = this.decryptHybridCTR(ciphertext, options.tag, options.nonce, options?.aad, options?.tweak)
        if (hybridCtrResult === null) {
          return this.handleDecryptionFailure("HybridCTR authentication failed")
        }
        return hybridCtrResult
      
      default:
        throw new Error(`Decryption not implemented for mode: ${this.mode}`)
    }
  }

  /**
   * Cifra datos de texto.
   * @param plaintext El texto a cifrar
   * @param options Opciones adicionales como IV, AAD, etc.
   * @returns Resultado de cifrado con texto cifrado como cadena y posiblemente etiqueta/iv
   */
  public encryptText(plaintext: string, options?: {
    iv?: Uint8Array,
    aad?: Uint8Array,
    nonce?: Uint8Array,
    tweak?: Uint8Array
  }): TextEncryptionResult {
    const textEncoder = new TextEncoder()
    const data = textEncoder.encode(plaintext)
    const result = this.encrypt(data, options)
    
    return {
      ...result,
      ciphertext: this.arrayBufferToBase64(result.ciphertext)
    }
  }

  /**
   * Descifra datos de texto.
   * @param ciphertext El texto cifrado a descifrar
   * @param options Opciones adicionales como IV, etiqueta, AAD, etc.
   * @returns Texto plano descifrado
   */
  public decryptText(ciphertext: string, options?: {
    iv?: Uint8Array,
    tag?: Uint8Array,
    aad?: Uint8Array,
    nonce?: Uint8Array,
    tweak?: Uint8Array
  }): string {
    const data = this.base64ToArrayBuffer(ciphertext)
    const result = this.decrypt(data, options)
    const textDecoder = new TextDecoder()
    return textDecoder.decode(result)
  }

  /**
   * Cifra datos de texto con un alfabeto específico (para modos FPE).
   * @param plaintext El texto a cifrar
   * @param alphabet El alfabeto a usar para modos FPE
   * @param options Opciones adicionales como IV, AAD, etc.
   * @returns Texto cifrado
   */
  public encryptTextWithAlphabet(plaintext: string, alphabet: string, options?: {
    iv?: Uint8Array,
    aad?: Uint8Array,
    nonce?: Uint8Array,
    tweak?: Uint8Array
  }): string {
    if (this.mode === AesMode.FPE_FF1) {
      const fpe = new ModeOfOperationFPE_FF1(this.key, alphabet);
      const tweak = options?.tweak || new Uint8Array(0);
      return fpe.encrypt(plaintext, tweak);
    }
    throw new Error("Alphabet-based encryption only supported for FPE-FF1 mode");
  }

  /**
   * Descifra datos de texto con un alfabeto específico (para modos FPE).
   * @param ciphertext El texto cifrado a descifrar
   * @param alphabet El alfabeto a usar para modos FPE
   * @param options Opciones adicionales como IV, etiqueta, AAD, etc.
   * @returns Texto plano descifrado
   */
  public decryptTextWithAlphabet(ciphertext: string, alphabet: string, options?: {
    iv?: Uint8Array,
    tag?: Uint8Array,
    aad?: Uint8Array,
    nonce?: Uint8Array,
    tweak?: Uint8Array
  }): string {
    if (this.mode === AesMode.FPE_FF1) {
      const fpe = new ModeOfOperationFPE_FF1(this.key, alphabet);
      const tweak = options?.tweak || new Uint8Array(0);
      return fpe.decrypt(ciphertext, tweak);
    }
    throw new Error("Alphabet-based decryption only supported for FPE-FF1 mode");
  }

  /**
   * Cifra datos de archivo.
   * @param fileData Los datos del archivo a cifrar
   * @param options Opciones adicionales como IV, AAD, etc.
   * @returns Resultado de cifrado
   */
  public encryptFile(fileData: Uint8Array, options?: {
    iv?: Uint8Array,
    aad?: Uint8Array,
    nonce?: Uint8Array,
    tweak?: Uint8Array
  }): EncryptionResult {
    return this.encrypt(fileData, options)
  }

  /**
   * Descifra datos de archivo.
   * @param fileData Los datos del archivo cifrado a descifrar
   * @param options Opciones adicionales como IV, etiqueta, AAD, etc.
   * @returns Datos del archivo descifrado
   */
  public decryptFile(fileData: Uint8Array, options?: {
    iv?: Uint8Array,
    tag?: Uint8Array,
    aad?: Uint8Array,
    nonce?: Uint8Array,
    tweak?: Uint8Array
  }): Uint8Array {
    return this.decrypt(fileData, options)
  }

  // --- Private implementation methods ---

  private handleDecryptionFailure(message: string): never {
    throw new Error(message)
  }

  private arrayBufferToBase64(buffer: Uint8Array): string {
    let binary = ""
    const bytes = new Uint8Array(buffer)
    const len = bytes.byteLength
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i])
    }
    return btoa(binary)
  }

  private base64ToArrayBuffer(base64: string): Uint8Array {
    const binaryString = atob(base64)
    const bytes = new Uint8Array(binaryString.length)
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i)
    }
    return bytes
  }

  // --- Mode-specific encryption methods ---

  private encryptECB(plaintext: Uint8Array): EncryptionResult {
    // Pad plaintext to multiple of 16 bytes
    const paddedPlaintext = this.padPkcs7(plaintext)
    const ecb = new ModeOfOperationECB(this.key)
    const ciphertext = ecb.encrypt(paddedPlaintext)
    return { ciphertext }
  }

  private decryptECB(ciphertext: Uint8Array): Uint8Array {
    const ecb = new ModeOfOperationECB(this.key)
    const plaintext = ecb.decrypt(ciphertext)
    return this.unpadPkcs7(plaintext)
  }

  private encryptCBC(plaintext: Uint8Array, iv?: Uint8Array): EncryptionResult {
    const actualIv = iv || this.generateRandomIv()
    // Pad plaintext to multiple of 16 bytes
    const paddedPlaintext = this.padPkcs7(plaintext)
    const cbc = new ModeOfOperationCBC(this.key, actualIv)
    const ciphertext = cbc.encrypt(paddedPlaintext)
    return { ciphertext, iv: actualIv }
  }

  private decryptCBC(ciphertext: Uint8Array, iv?: Uint8Array): Uint8Array {
    if (!iv) {
      throw new Error("CBC mode requires an IV")
    }
    const cbc = new ModeOfOperationCBC(this.key, iv)
    const plaintext = cbc.decrypt(ciphertext)
    return this.unpadPkcs7(plaintext)
  }

  private encryptCTR(plaintext: Uint8Array, iv?: Uint8Array): EncryptionResult {
    const actualIv = iv || this.generateRandomIv()
    const ctr = new ModeOfOperationCTR(this.key, actualIv)
    const ciphertext = ctr.encrypt(plaintext)
    return { ciphertext, iv: actualIv }
  }

  private decryptCTR(ciphertext: Uint8Array, iv?: Uint8Array): Uint8Array {
    if (!iv) {
      throw new Error("CTR mode requires an IV")
    }
    const ctr = new ModeOfOperationCTR(this.key, iv)
    return ctr.decrypt(ciphertext)
  }

  private encryptCFB(plaintext: Uint8Array, iv?: Uint8Array): EncryptionResult {
    const actualIv = iv || this.generateRandomIv()
    const cfb = new ModeOfOperationCFB(this.key, actualIv)
    const ciphertext = cfb.encrypt(plaintext)
    return { ciphertext, iv: actualIv }
  }

  private decryptCFB(ciphertext: Uint8Array, iv?: Uint8Array): Uint8Array {
    if (!iv) {
      throw new Error("CFB mode requires an IV")
    }
    const cfb = new ModeOfOperationCFB(this.key, iv)
    return cfb.decrypt(ciphertext)
  }

  private encryptOFB(plaintext: Uint8Array, iv?: Uint8Array): EncryptionResult {
    const actualIv = iv || this.generateRandomIv()
    const ofb = new ModeOfOperationOFB(this.key, actualIv)
    const ciphertext = ofb.encrypt(plaintext)
    return { ciphertext, iv: actualIv }
  }

  private decryptOFB(ciphertext: Uint8Array, iv?: Uint8Array): Uint8Array {
    if (!iv) {
      throw new Error("OFB mode requires an IV")
    }
    const ofb = new ModeOfOperationOFB(this.key, iv)
    return ofb.decrypt(ciphertext)
  }

  private encryptGCM(plaintext: Uint8Array, iv?: Uint8Array, aad?: Uint8Array): EncryptionResult {
    const actualIv = iv || this.generateRandomIv(12) // GCM typically uses 12-byte IV
    const gcm = new ModeOfOperationGCM(this.key, actualIv)
    const result = gcm.encrypt(plaintext, aad)
    return { ciphertext: result.ciphertext, tag: result.tag, iv: actualIv }
  }

  private decryptGCM(ciphertext: Uint8Array, tag: Uint8Array, iv?: Uint8Array, aad?: Uint8Array): Uint8Array | null {
    if (!iv) {
      throw new Error("GCM mode requires an IV")
    }
    const gcm = new ModeOfOperationGCM(this.key, iv)
    return gcm.decrypt(ciphertext, tag, aad)
  }

  private encryptCCM(plaintext: Uint8Array, nonce?: Uint8Array, aad?: Uint8Array): EncryptionResult {
    if (!nonce) {
      throw new Error("CCM mode requires a nonce")
    }
    const ccm = new ModeOfOperationCCM(this.key, this.tagSize || 16)
    const result = ccm.encrypt(plaintext, nonce, aad || new Uint8Array(0))
    return { ciphertext: result.ciphertext, tag: result.tag, iv: nonce }
  }

  private decryptCCM(ciphertext: Uint8Array, tag: Uint8Array, nonce?: Uint8Array, aad?: Uint8Array): Uint8Array | null {
    if (!nonce) {
      throw new Error("CCM mode requires a nonce")
    }
    const ccm = new ModeOfOperationCCM(this.key, tag.length)
    return ccm.decrypt(ciphertext, nonce, tag, aad || new Uint8Array(0))
  }

  private encryptEAX(plaintext: Uint8Array, nonce?: Uint8Array, aad?: Uint8Array): EncryptionResult {
    const actualNonce = nonce || this.generateRandomIv()
    const eax = new ModeOfOperationEAX(this.key, this.tagSize || 16)
    const result = eax.encrypt(plaintext, actualNonce, aad || new Uint8Array(0))
    return { ciphertext: result.ciphertext, tag: result.tag, iv: actualNonce }
  }

  private decryptEAX(ciphertext: Uint8Array, tag: Uint8Array, nonce?: Uint8Array, aad?: Uint8Array): Uint8Array | null {
    if (!nonce) {
      throw new Error("EAX mode requires a nonce")
    }
    const eax = new ModeOfOperationEAX(this.key, tag.length)
    return eax.decrypt(ciphertext, tag, nonce, aad || new Uint8Array(0))
  }

  private encryptCWC(plaintext: Uint8Array, iv?: Uint8Array, aad?: Uint8Array): EncryptionResult {
    const actualIv = iv || this.generateRandomIv()
    const cwc = new ModeOfOperationCWC(this.key)
    const result = cwc.encrypt(plaintext, actualIv, aad || new Uint8Array(0))
    return { ciphertext: result.ciphertext, tag: result.tag, iv: actualIv }
  }

  private decryptCWC(ciphertext: Uint8Array, tag: Uint8Array, iv?: Uint8Array, aad?: Uint8Array): Uint8Array | null {
    if (!iv) {
      throw new Error("CWC mode requires an IV")
    }
    const cwc = new ModeOfOperationCWC(this.key)
    return cwc.decrypt(ciphertext, tag, iv, aad || new Uint8Array(0))
  }

  private encryptGCM_SIV(plaintext: Uint8Array, nonce?: Uint8Array, aad?: Uint8Array): EncryptionResult {
    if (!nonce) {
      throw new Error("GCM-SIV mode requires a nonce")
    }
    const gcmSiv = new ModeOfOperationGCM_SIV(this.key)
    const result = gcmSiv.encrypt(plaintext, nonce, aad || new Uint8Array(0))
    return { ciphertext: result.ciphertext, tag: result.tag, iv: nonce }
  }

  private decryptGCM_SIV(ciphertext: Uint8Array, tag: Uint8Array, nonce?: Uint8Array, aad?: Uint8Array): Uint8Array | null {
    if (!nonce) {
      throw new Error("GCM-SIV mode requires a nonce")
    }
    const gcmSiv = new ModeOfOperationGCM_SIV(this.key)
    return gcmSiv.decrypt(ciphertext, tag, nonce, aad || new Uint8Array(0))
  }

  private encryptOCB(plaintext: Uint8Array, nonce?: Uint8Array, aad?: Uint8Array): EncryptionResult {
    if (!nonce) {
      throw new Error("OCB mode requires a nonce")
    }
    const ocb = new ModeOfOperationOCB(this.key, this.tagSize || 16)
    const result = ocb.encrypt(plaintext, nonce, aad || new Uint8Array(0))
    return { ciphertext: result.ciphertext, tag: result.tag, iv: nonce }
  }

  private decryptOCB(ciphertext: Uint8Array, tag: Uint8Array, nonce?: Uint8Array, aad?: Uint8Array): Uint8Array | null {
    if (!nonce) {
      throw new Error("OCB mode requires a nonce")
    }
    const ocb = new ModeOfOperationOCB(this.key, tag.length)
    return ocb.decrypt(ciphertext, tag, nonce, aad || new Uint8Array(0))
  }

  private encryptXTS(plaintext: Uint8Array, tweak: Uint8Array): EncryptionResult {
    const xts = new ModeOfOperationXTS(this.key)
    const ciphertext = xts.encrypt(plaintext, tweak)
    return { ciphertext }
  }

  private decryptXTS(ciphertext: Uint8Array, tweak: Uint8Array): Uint8Array {
    const xts = new ModeOfOperationXTS(this.key)
    return xts.decrypt(ciphertext, tweak)
  }

  private encryptKW(plaintext: Uint8Array): EncryptionResult {
    const kw = new ModeOfOperationKW(this.key)
    const ciphertext = kw.wrap(plaintext)
    return { ciphertext }
  }

  private decryptKW(ciphertext: Uint8Array): Uint8Array | null {
    const kw = new ModeOfOperationKW(this.key)
    return kw.unwrap(ciphertext)
  }

  private encryptKWP(plaintext: Uint8Array): EncryptionResult {
    const kwp = new ModeOfOperationKWP(this.key)
    const ciphertext = kwp.wrap(plaintext)
    return { ciphertext }
  }

  private decryptKWP(ciphertext: Uint8Array): Uint8Array | null {
    const kwp = new ModeOfOperationKWP(this.key)
    return kwp.unwrap(ciphertext)
  }

  private encryptFPE_FF1(plaintext: string, tweak?: Uint8Array): EncryptionResult {
    // FPE-FF1 works differently - it encrypts strings and returns strings
    // This is a special case that doesn't fit the standard binary encryption model
    throw new Error("FPE-FF1 requires alphabet specification, use encryptTextWithAlphabet method instead");
  }

  private decryptFPE_FF1(ciphertext: string, tweak?: Uint8Array): string {
    // FPE-FF1 works differently - it decrypts strings and returns strings
    // This is a special case that doesn't fit the standard binary encryption model
    throw new Error("FPE-FF1 requires alphabet specification, use decryptTextWithAlphabet method instead");
  }

  private generateCBC_MAC(plaintext: Uint8Array, tagSize?: number): EncryptionResult {
    const cbcMac = new ModeOfOperationCBC_MAC(this.key)
    const tag = cbcMac.generateTag(plaintext, tagSize || 16)
    return { ciphertext: new Uint8Array(0), tag }
  }

  private encryptPMAC_SIV(plaintext: Uint8Array, nonce?: Uint8Array, aad?: Uint8Array): EncryptionResult {
    const actualNonce = nonce || this.generateRandomIv()
    const pmacSiv = new ModeOfOperationPMAC_SIV(this.key, this.tagSize || 16)
    const result = pmacSiv.encrypt(plaintext, actualNonce, aad || new Uint8Array(0))
    return { ciphertext: result.ciphertext, tag: result.iv_tag, iv: actualNonce }
  }

  private decryptPMAC_SIV(ciphertext: Uint8Array, tag: Uint8Array, nonce?: Uint8Array, aad?: Uint8Array): Uint8Array | null {
    if (!nonce) {
      throw new Error("PMAC-SIV mode requires a nonce")
    }
    const pmacSiv = new ModeOfOperationPMAC_SIV(this.key, tag.length)
    return pmacSiv.decrypt(ciphertext, tag, nonce, aad || new Uint8Array(0))
  }

  private encryptTKW(plaintext: Uint8Array, tweak: Uint8Array): EncryptionResult {
    const tkw = new ModeOfOperationTKW(this.key)
    const ciphertext = tkw.wrap(plaintext, tweak)
    return { ciphertext }
  }

  private decryptTKW(ciphertext: Uint8Array, tweak: Uint8Array): Uint8Array | null {
    const tkw = new ModeOfOperationTKW(this.key)
    return tkw.unwrap(ciphertext, tweak)
  }

  private encryptHybridCTR(plaintext: Uint8Array, nonce?: Uint8Array, aad?: Uint8Array, tweak?: Uint8Array): EncryptionResult {
    const hybridCtr = new ModeOfOperationHybridCTR(this.key, this.tagSize || 16)
    const result = hybridCtr.encrypt(plaintext, nonce, aad || new Uint8Array(0), tweak || new Uint8Array(16))
    return { ciphertext: result.ciphertext, tag: result.tag, iv: result.nonce }
  }

  private decryptHybridCTR(ciphertext: Uint8Array, tag: Uint8Array, nonce?: Uint8Array, aad?: Uint8Array, tweak?: Uint8Array): Uint8Array | null {
    if (!nonce) {
      throw new Error("HybridCTR mode requires a nonce")
    }
    const hybridCtr = new ModeOfOperationHybridCTR(this.key, tag.length)
    return hybridCtr.decrypt(ciphertext, tag, nonce, aad || new Uint8Array(0), tweak || new Uint8Array(16))
  }

  // --- Padding methods ---

  private padPkcs7(data: Uint8Array): Uint8Array {
    const blockSize = 16
    const padding = blockSize - (data.length % blockSize)
    const paddedData = new Uint8Array(data.length + padding)
    paddedData.set(data)
    for (let i = data.length; i < paddedData.length; i++) {
      paddedData[i] = padding
    }
    return paddedData
  }

  private unpadPkcs7(data: Uint8Array): Uint8Array {
    if (data.length === 0) return data
    const padding = data[data.length - 1]
    if (padding > 16) return data
    return data.slice(0, data.length - padding)
  }

  // --- Utility methods ---

  private generateRandomIv(length: number = 16): Uint8Array {
    const iv = new Uint8Array(length)
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(iv)
    } else {
      // Fallback for environments without crypto.getRandomValues
      for (let i = 0; i < length; i++) {
        iv[i] = Math.floor(Math.random() * 256)
      }
    }
    return iv
  }
}
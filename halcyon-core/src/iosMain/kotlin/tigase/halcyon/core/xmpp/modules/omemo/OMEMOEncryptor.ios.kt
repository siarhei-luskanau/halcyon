package tigase.halcyon.core.xmpp.modules.omemo

import korlibs.crypto.encoding.hex
import kotlinx.cinterop.*
import platform.Foundation.NSInputStream
import platform.Foundation.NSOutputStream
import platform.Security.SecRandomCopyBytes
import platform.Security.kSecRandomDefault
import tigase.halcyon.core.fromBase64
import tigase.halcyon.core.logger.LoggerFactory
import tigase.halcyon.core.toBase64
import tigase.halcyon.core.xml.Element
import tigase.halcyon.core.xml.element
import tigase.halcyon.core.xmpp.modules.mix.getMixAnnotation
import tigase.halcyon.core.xmpp.stanzas.Message
import tigase.halcyon.core.xmpp.toBareJID

actual object OMEMOEncryptor {
    
    private val log = LoggerFactory.logger("tigase.halcyon.core.xmpp.modules.omemo.OMEMOEncryptor")
    private val engine = AesGcmEngine();
    
    private fun retrieveKey(
        keyElements: List<Element>,
        senderAddr: SignalProtocolAddress,
        store: SignalProtocolStore,
        session: OMEMOSession,
        healSession: (SignalProtocolAddress) -> Unit
    ): DecryptedKey? {
        val localKeys = keyElements.filter { it.attributes["rid"]?.toInt() == session.localRegistrationId };
        val iterator = localKeys.iterator()
        val sessionCipher = SessionCipher(store, senderAddr)
        while (iterator.hasNext()) {
            val keyElement = iterator.next()
            val preKey = keyElement.attributes["prekey"] in listOf("1", "true")
            val encryptedKey = keyElement.value?.fromBase64() ?: continue

            
            try {
                return DecryptedKey(sessionCipher.decrypt(data = encryptedKey, isPreKey = preKey), preKey);
            } catch (e: Exception) {
                // should we try to heal sessions?
                if (e is SignalException) {
                    when (e.error) {
                        // we need to try to recover
                        SignalError.invalidMessage, SignalError.noSession, SignalError.noSession -> healSession(senderAddr)
                        else -> {}
                    }
                }
                log.warning(e, { "failed to decrypt key for " + sessionCipher.address + ", store = " + sessionCipher.store + ", error: " + e.cause })
                e.printStackTrace();
                if (iterator.hasNext()) {
                    continue
                }
                throw e
            }
        }
        return null
    }

    private fun findKeyElements(encElement: Element): List<Element> =
        encElement.getFirstChild("header")?.getChildren("key") ?: emptyList()

    data class DecryptedKey(val key: ByteArray, val isPreKey: Boolean) {}
    
    actual fun decrypt(
        store: SignalProtocolStore,
        session: OMEMOSession,
        stanza: Message,
        healSession: (SignalProtocolAddress)->Unit
    ): OMEMOMessage {
        var hasCipherText = false
        try {
            val myAddr = SignalProtocolAddress(session.localJid.toString(), session.localRegistrationId)
            val encElement =
                stanza.getChildrenNS("encrypted", OMEMOModule.XMLNS) ?: throw OMEMOException.NoEncryptedElement()
            val ciphertext = encElement.getFirstChild("payload")?.value?.fromBase64()?.also {
                hasCipherText = true
            }
            val senderId = encElement.getFirstChild("header")?.attributes?.get("sid")?.toInt()
                ?: throw OMEMOException.NoSidAttribute()
            val senderAddr = SignalProtocolAddress((stanza.getMixAnnotation()?.jid ?: stanza.attributes["from"]!!.toBareJID()).toString(), senderId)
            val iv = encElement.getFirstChild("header")?.getFirstChild("iv")?.value?.fromBase64()
                ?: throw OMEMOException.NoIV()

            // extracting inner key
            var decryptedKey =
                retrieveKey(findKeyElements(encElement), senderAddr, store, session, healSession)
                    ?: throw OMEMOException.DeviceKeyNotFoundException();

            ciphertext?.let { ciphertext ->
                val key = decryptedKey.key;
                if (key.size < 32) {
                    throw OMEMOException.InvalidKeyLengthException();
                }

                val authtaglength = key.size - 16
                val newCipherText = ciphertext.copyOf().plus(key.copyOfRange(16, 16 + authtaglength));
                val newKey = key.copyOfRange(0, 16);

                val result = engine.decrypt(iv, key, ciphertext, null);
                
                val decryptedBody =(result?.decodeToString()) ?: "Cannot decrypt message.";
                stanza.replaceBody(decryptedBody)
            }

            return OMEMOMessage.Decrypted(stanza, senderAddr, store.getIdentity(senderAddr)!!.publicKey.serialize().hex, decryptedKey.isPreKey);
        } catch (e: Exception) {
            log.warning(e) { "Cannot decrypt message: ${stanza.getAsString()}" }
            val condition = when (e) {
                is OMEMOException -> e.condition
                is SignalException -> when (e.error) {
                    SignalError.duplicateMessage -> OMEMOErrorCondition.DuplicateMessage
                    else -> OMEMOErrorCondition.CannotDecrypt
                }
                else -> OMEMOErrorCondition.CannotDecrypt
            }
            if (hasCipherText) {
                stanza.replaceBody(condition.message())
            }
            return OMEMOMessage.Error(stanza, condition)
        }
    }
    
    @OptIn(ExperimentalForeignApi::class)
    fun generateIV(): ByteArray {
        val data = ByteArray(12);
        SecRandomCopyBytes(kSecRandomDefault, 12.toULong(), data.toCValues());
        return data;
    }
    
    @OptIn(ExperimentalForeignApi::class)
    fun generateKey(keySize: Int = 128): ByteArray {
        val keySizeInBytes = keySize / 8;
        val data = ByteArray(keySizeInBytes);
        SecRandomCopyBytes(kSecRandomDefault, keySizeInBytes.toULong(), data.toCValues());
        return data;
    }

    actual fun encrypt(
        session: OMEMOSession,
        plaintext: String?
    ): Element {
        log.finest("encrypting message started...");
        log.finest("generating IV...")
        val iv = generateIV()
        log.finest("generating key...")
        val keyData = generateKey()

        log.finest("encrypting with AES...")
        val encrypted = plaintext?.let { engine.encrypt(iv, keyData, it.encodeToByteArray()) }?.also {
            log.finest("encrypted with AES and got " + it.data.size + " bytes")
        }

        val authtagPlusInnerKey = encrypted?.let { keyData.plus(it.tag) } ?: keyData

        return element("encrypted") {
            xmlns = OMEMOModule.XMLNS

            "header" {
                attributes["sid"] = "${session.localRegistrationId}"
                "iv" {
                    +iv.toBase64()
                }
                session.ciphers.forEach { (addr, sessionCipher) ->
                    log.finest("adding encryption key for " + addr.deviceId)
                    "key" {
                        attributes["rid"] = addr.deviceId.toString()
                        
                        val m = sessionCipher.encrypt(authtagPlusInnerKey)
                        if (m.isPreKey) {
                            attributes["prekey"] = "true"
                        }
                        
                        +m.data.toBase64()
                    }
                }
            }

            encrypted?.let { encrypted ->
                "payload" {
                    +encrypted.data.toBase64()
                }
            }
        }
    }

}

class AesGcmCipher(val iv: ByteArray, val key: ByteArray) {
    val engine = AesGcmEngine();
}

@OptIn(ExperimentalForeignApi::class)
class AesGcmEngine {

    fun decrypt(iv: ByteArray, key: ByteArray, payload: ByteArray, tag: ByteArray?): ByteArray? {

        return iv;
    }

    sealed class DecryptionStep {
        class InputChunk(val data: ByteArray): DecryptionStep()
        class EndOfInput(val authTag: ByteArray?): DecryptionStep()
    }

    fun decrypt(iv: ByteArray, key: ByteArray, chunkProvider: () -> DecryptionStep, chunkConsumer: (UByteArray) -> Unit) {
        iv
    }

    fun decrypt(iv: ByteArray, key: ByteArray, hasAuthTag: Boolean = true, input: NSInputStream, inputLength: Int, output: NSOutputStream) {
        val len = if (hasAuthTag) { inputLength - 16 } else { inputLength }
        var consumed = 0;
        decrypt(iv, key, chunkProvider = {
            memScoped {
                val maxSize = minOf(4096, len - consumed);
                if (maxSize > 0) {
                    val buffer = allocArray<UByteVar>(maxSize);
                    val read = input.read(buffer, maxSize.toULong()).toInt();
                    if (read >= 0) {
                        consumed += read;
                        return@memScoped DecryptionStep.InputChunk(data = buffer.readBytes(read));
                    } else {
                        return@memScoped DecryptionStep.EndOfInput(authTag = null)
                    }
                }

                if (hasAuthTag) {
                    val buffer = allocArray<UByteVar>(16);
                    val read = input.read(buffer, 16u).toInt();
                    return@memScoped DecryptionStep.EndOfInput(authTag = buffer.readBytes(read));
                } else {
                    TODO("SHOULD NOT HAPPEN!");
                }
            }
        }, chunkConsumer = {
            memScoped {
                output.write(it.toCValues().ptr, it.size.toULong());
            }
        })
    }

    fun decrypt(iv: ByteArray, key: ByteArray, hasAuthTag: Boolean = true, input: NSInputStream, inputLength: Int): ByteArray {
        var result = ByteArray(0);
        val len = if (hasAuthTag) { inputLength - 16 } else { inputLength }
        var consumed = 0;
        decrypt(iv, key, chunkProvider = {
            memScoped {
                val maxSize = minOf(4096, len - consumed);
                if (maxSize > 0) {
                    val buffer = allocArray<UByteVar>(maxSize);
                    val read = input.read(buffer, maxSize.toULong()).toInt();
                    if (read >= 0) {
                        consumed += read;
                        return@memScoped DecryptionStep.InputChunk(data = buffer.readBytes(read));
                    } else {
                        return@memScoped DecryptionStep.EndOfInput(authTag = null)
                    }
                }

                if (hasAuthTag) {
                    val buffer = allocArray<UByteVar>(16);
                    val read = input.read(buffer, 16u).toInt();
                    return@memScoped DecryptionStep.EndOfInput(authTag = buffer.readBytes(read));
                } else {
                    TODO("SHOULD NOT HAPPEN!");
                }
            }
        }, chunkConsumer = {
            result = result.plus(it.toByteArray());
        })
        return result;
    }

    class Encrypted(val data: ByteArray, val tag: ByteArray) {}

    fun encrypt(iv: ByteArray, key: ByteArray, payload: ByteArray): Encrypted {
         return Encrypted(iv, iv);
    }

    fun encrypt(iv: ByteArray, key: ByteArray, includeAuthTag: Boolean = true, chunkProvider: () -> EncryptionStep, chunkConsumer: (UByteArray) -> Unit) {
        iv;
    }

    sealed class EncryptionStep {
        class InputChunk(val data: ByteArray): EncryptionStep() {}
        class EndOfInput: EncryptionStep() {}
    }

    fun encrypt(iv: ByteArray, key: ByteArray, includeAuthTag: Boolean = true, input: NSInputStream, output: NSOutputStream) {
        encrypt(iv, key, includeAuthTag, chunkProvider = {
            memScoped {
                val buffer = allocArray<UByteVar>(4096);
                val read = input.read(buffer, 4096u).toInt();
                if (read > 0) {
                    return@memScoped EncryptionStep.InputChunk(buffer.readBytes(read));
                } else {
                    return@memScoped EncryptionStep.EndOfInput();
                }
            }
        }, chunkConsumer = { chunk ->
            memScoped {
                output.write(chunk.toCValues().ptr, chunk.size.toULong());
            }
        })
    }

    fun encrypt(iv: ByteArray, key: ByteArray, includeAuthTag: Boolean = true, input: NSInputStream): ByteArray {
        var result = ByteArray(0)
        encrypt(iv, key, includeAuthTag, chunkProvider = {
            memScoped {
                val buffer = allocArray<UByteVar>(4096);
                val read = input.read(buffer, 4096u).toInt();
                if (read > 0) {
                    return@memScoped EncryptionStep.InputChunk(buffer.readBytes(read));
                } else {
                    return@memScoped EncryptionStep.EndOfInput();
                }
            }
        }, chunkConsumer = { chunk ->
            result = result.plus(chunk.toByteArray());
        })
        return result;
    }

}

private fun Message.replaceBody(newBody: String) {
    this.getChildren("body").forEach { this.remove(it) }
    this.add(element("body") {
        +newBody
    })
}

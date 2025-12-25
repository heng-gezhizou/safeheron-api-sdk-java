package com.safeheron.client.utils;

import com.safeheron.client.config.RSATypeEnum;

/**
 * External RSA provider interface for delegating RSA cryptographic operations
 * to external key management or signing systems.
 *
 * <p>This interface is designed to support scenarios where RSA private keys
 * are managed by secure infrastructures such as HSM, KMS, or other
 * centralized key management services. In such environments, private key
 * material must never be exported or exposed to the application layer.</p>
 *
 * <p>By introducing this abstraction, the SDK can delegate RSA signing and
 * decryption operations to external systems via a {@code keyId}, instead of
 * requiring the complete private key to be configured locally.</p>
 *
 * <p>Typical use cases include:</p>
 * <ul>
 *   <li>Private keys stored in HSM or cloud KMS (AWS KMS, Azure Key Vault, etc.)</li>
 *   <li>Compliance-driven environments where private keys are prohibited from leaving secure boundaries</li>
 *   <li>Custom or enterprise-grade signing services</li>
 * </ul>
 *
 * <p>Implementations of this interface are responsible for:</p>
 * <ul>
 *   <li>Resolving the {@code keyId} to the actual RSA key in the external system</li>
 *   <li>Executing the appropriate RSA algorithm (PKCS#1 v1.5, RSA-PSS, etc.)</li>
 *   <li>Ensuring cryptographic correctness and security of the operation</li>
 * </ul>
 *
 * <p>The SDK itself does not hold, persist, or process any RSA private key
 * material when this provider is used.</p>
 *
 * @author Jiahj
 */
public interface ExternalRsaProvider {
    /**
     * Sign the given content using RSA (PKCS#1 v1.5) with a key managed by an external system
     * such as HSM or KMS.
     *
     * <p>The actual private key material must never be exposed to the SDK.
     * Implementations should perform the signing operation by delegating to
     * the external key management or signing service identified by {@code keyId}.</p>
     *
     * @param content the plain text content to be signed
     * @param keyId   the identifier of the RSA key in the external signing system
     * @return the Base64-encoded signature result
     */
    String sign(String content, String keyId);

    /**
     * Sign the given content using RSA-PSS with a key managed by an external system
     * such as HSM or KMS.
     *
     * <p>This method is intended for scenarios requiring stronger cryptographic
     * security guarantees compared to PKCS#1 v1.5.</p>
     *
     * @param content the plain text content to be signed
     * @param keyId   the identifier of the RSA key in the external signing system
     * @return the Base64-encoded RSA-PSS signature result
     */
    String signPSS(String content, String keyId);

    /**
     * Decrypt the given encrypted content using an RSA private key managed by
     * an external system such as HSM or KMS.
     *
     * <p>The decryption operation must be performed by the external key management
     * system, and the private key material must not be exposed to the SDK.</p>
     *
     * @param content the encrypted content, typically Base64-encoded
     * @param keyId   the identifier of the RSA key in the external key management system
     * @param rsaType the RSA algorithm type used for decryption
     * @return the decrypted raw byte array
     */
    byte[] decrypt(String content, String keyId, RSATypeEnum rsaType);

}

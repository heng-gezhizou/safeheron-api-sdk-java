package com.safeheron.demo.api.transaction;

import com.safeheron.client.api.TransactionApiService;
import com.safeheron.client.config.RSATypeEnum;
import com.safeheron.client.config.SafeheronConfig;
import com.safeheron.client.request.CreateTransactionRequest;
import com.safeheron.client.response.TxKeyResult;
import com.safeheron.client.utils.ExternalRsaProvider;
import com.safeheron.client.utils.RsaUtil;
import com.safeheron.client.utils.ServiceCreator;
import com.safeheron.client.utils.ServiceExecutor;
import lombok.extern.slf4j.Slf4j;
import org.junit.BeforeClass;
import org.junit.Test;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;


/**
 * @author xigaoku
 */
@Slf4j
public class TransactionTest {

    static TransactionApiService transactionApi;

    static Map<String, Object> config;

    @BeforeClass
    public static void beforeClass() throws FileNotFoundException {
        Yaml yaml = new Yaml();
        File file = new File("src/test/resources/demo/api/transaction/config.yaml");
        InputStream inputStream = new FileInputStream(file);
        config = yaml.load(inputStream);

        transactionApi = ServiceCreator.create(TransactionApiService.class, SafeheronConfig.builder()
                .baseUrl(config.get("baseUrl").toString())
                .apiKey(config.get("apiKey").toString())
                .safeheronRsaPublicKey(config.get("safeheronPublicKey").toString())
                .rsaPrivateKey(config.get("privateKey").toString())
                .requestTimeout(Long.valueOf(config.get("requestTimeout").toString()))
                .build());
    }

    @Test
    public void testSendTransaction(){
        CreateTransactionRequest createTransactionRequest = new com.safeheron.client.request.CreateTransactionRequest();
        createTransactionRequest.setSourceAccountKey(config.get("accountKey").toString());
        createTransactionRequest.setSourceAccountType("VAULT_ACCOUNT");
        createTransactionRequest.setDestinationAccountType("ONE_TIME_ADDRESS");
        createTransactionRequest.setDestinationAddress(config.get("destinationAddress").toString());
        createTransactionRequest.setCoinKey("ETH_GOERLI");
        createTransactionRequest.setTxAmount("0.001");
        createTransactionRequest.setTxFeeLevel("MIDDLE");
        createTransactionRequest.setCustomerRefId(UUID.randomUUID().toString());
        TxKeyResult createTransactionResponse = ServiceExecutor.execute(transactionApi.createTransactions(createTransactionRequest));
        System.out.println(String.format("transaction has been created, txKey: %s", createTransactionResponse.getTxKey()));
    }

    /**
     * Test case for sending a transaction using an ExternalRsaProvider.
     *
     * <p>This test demonstrates how to integrate a custom {@link ExternalRsaProvider}
     * to perform RSA signing through an external system (e.g. HSM / KMS),
     * instead of configuring the complete RSA private key in the SDK.</p>
     *
     * <p>For demonstration purposes, this test uses a mock implementation
     * of {@code ExternalRsaProvider} that performs local RSA signing.
     * In real production scenarios, the signing logic should be delegated
     * to a secure key management or signing service, identified by {@code keyId}.</p>
     */
    @Test
    public void testSendTransactionWithExternalRsaProvider() {

        /**
         * Mock implementation of ExternalRsaProvider.
         *
         * <p>This implementation simulates an external signing system by
         * performing RSA signing locally using a private key loaded from
         * configuration. It is intended for testing and demonstration only.</p>
         */
        ExternalRsaProvider mockRsaProvider = new ExternalRsaProvider() {

            /**
             * Sign the given content using RSA (SHA256withRSA).
             *
             * <p>The {@code keyId} parameter is ignored in this mock implementation.
             * In real-world usage, {@code keyId} should be used to locate the
             * corresponding RSA key in an HSM or KMS.</p>
             */
            @Override
            public String sign(String content, String keyId) {
                try {
                    PrivateKey priKey = getPrivateKey("RSA", config.get("privateKey").toString());
                    Signature privateSignature = Signature.getInstance("SHA256WithRSA");
                    privateSignature.initSign(priKey);
                    privateSignature.update(content.getBytes(StandardCharsets.UTF_8));
                    byte[] signature = privateSignature.sign();
                    return Base64.getEncoder().encodeToString(signature);
                } catch (Exception ignored) {
                }
                return null;
            }

            /**
             * RSA-PSS signing is not implemented in this mock.
             *
             * <p>This method is intentionally left blank as the current test
             * does not require RSA-PSS signing.</p>
             */
            @Override
            public String signPSS(String content, String keyId) {
                return "";
            }

            /**
             * RSA decryption is not implemented in this mock.
             *
             * <p>This method is not required for transaction creation
             * in the current test scenario.</p>
             */
            @Override
            public byte[] decrypt(String content, String keyId, RSATypeEnum rsaType) {
                return new byte[0];
            }

            /**
             * Utility method to load an RSA private key from a Base64-encoded string.
             *
             * <p>This method is used only for test purposes to simulate
             * an external signing system.</p>
             */
            private PrivateKey getPrivateKey(String algorithm, String privateKey) throws Exception {
                KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
                byte[] privateKeyData = Base64.getDecoder().decode(privateKey.getBytes(StandardCharsets.UTF_8));
                return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyData));
            }
        };

        /**
         * Register the ExternalRsaProvider so that the SDK delegates
         * RSA signing operations to the external provider.
         */
        RsaUtil.setExtProvider(mockRsaProvider);

        /**
         * Build transaction creation request.
         */
        CreateTransactionRequest createTransactionRequest = new CreateTransactionRequest();
        createTransactionRequest.setSourceAccountKey(config.get("accountKey").toString());
        createTransactionRequest.setSourceAccountType("VAULT_ACCOUNT");
        createTransactionRequest.setDestinationAccountType("ONE_TIME_ADDRESS");
        createTransactionRequest.setDestinationAddress(config.get("destinationAddress").toString());
        createTransactionRequest.setCoinKey("USDT_METACOMP_ERC20_ETHEREUM_SEPOLIA");
        createTransactionRequest.setTxAmount("0.001");
        createTransactionRequest.setTxFeeLevel("MIDDLE");
        createTransactionRequest.setCustomerRefId(UUID.randomUUID().toString());
        TxKeyResult createTransactionResponse = ServiceExecutor.execute(transactionApi.createTransactions(createTransactionRequest));
        System.out.println(String.format("transaction has been created, txKey: %s", createTransactionResponse.getTxKey()));
    }

}

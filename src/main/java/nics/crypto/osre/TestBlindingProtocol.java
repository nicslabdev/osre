package nics.crypto.osre;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Logger;

import nics.crypto.ntrureencrypt.Utils;

import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.encrypt.NtruEncrypt;
import net.sf.ntru.encrypt.EncryptionPrivateKey;
import net.sf.ntru.encrypt.EncryptionPublicKey;
import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.polynomial.IntegerPolynomial;

import nics.crypto.ntrureencrypt.NTRUReEncryptParams;
import nics.crypto.ntrureencrypt.NTRUReEncrypt;
import nics.crypto.ntrureencrypt.ReEncryptionKey;

public class TestBlindingProtocol {

    static Logger logger = Logger.getLogger(TestBlindingProtocol.class.getName());
    
    public static void main(String[] args) throws Exception {

        SecureRandom sRNG = new SecureRandom();

        int numBits = 8;
        //BigInteger prime = new BigInteger("66333221577766244971668217470771604112433242586277759383795847128687502424749");
        BigInteger prime = new BigInteger("229");
        BigInteger m = new BigInteger(numBits, sRNG).mod(prime);
        logger.info("Secret generated: " + m.toString());

        // Params
        String paramSpecs = "EES1087EP2_FAST";
        EncryptionParameters params = NTRUReEncryptParams.getParams(paramSpecs);
        NTRUReEncrypt ntruReEncrypt = new NTRUReEncrypt(params);

        // Keys
        EncryptionKeyPair keyPairA = ntruReEncrypt.generateKeyPair();
        EncryptionKeyPair keyPairB = ntruReEncrypt.generateKeyPair();

        // Encrypt
        IntegerPolynomial polyMessage = ntruReEncrypt.encodeMessage(
            Utils.bigIntegerToBitArray(m), 
            SecureRandom.getSeed(64), 
            NTRUReEncryptParams.getDM0(paramSpecs)
        );
        IntegerPolynomial polyCiphertext = ntruReEncrypt.encrypt(keyPairA.getPublic(), polyMessage, SecureRandom.getSeed(64));

        ReEncryptionKey rkAB = ntruReEncrypt.generateReEncryptionKey(keyPairA, keyPairB);
        IntegerPolynomial rkABmod = rkAB.rk.toIntegerPolynomial();
        rkABmod.modCenter(params.q);
        logger.info(Arrays.toString(rkABmod.coeffs));

        IntegerPolynomial fA = ntruReEncrypt.privatePolynomial(keyPairA.getPrivate());
        IntegerPolynomial fB = ntruReEncrypt.privatePolynomial(keyPairB.getPrivate());

        // Blinding protocol to derive RK
        IntegerPolynomial r = ntruReEncrypt.sampleBlinding(sRNG);

        //IntegerPolynomial rA = r.clone().mult(fA, params.q);
        IntegerPolynomial rA = ntruReEncrypt.blindPrivateKey(r, keyPairA.getPrivate());
        //logger.info(Arrays.toString(rA.coeffs));

        //IntegerPolynomial rABinv = rA.clone().mult(fB.invertFq(params.q), params.q);
        IntegerPolynomial rABinv = ntruReEncrypt.blindInversePrivateKey(rA, keyPairB.getPrivate());
        //logger.info(Arrays.toString(rABinv.coeffs));

        //IntegerPolynomial rinv = r.clone().invertFq(params.q);
        //IntegerPolynomial ABinv = rABinv.mult(rinv, params.q);
        IntegerPolynomial ABinv = ntruReEncrypt.extractBlinding(r, rABinv);
        //ABinv.modCenter(params.q);
        //logger.info(Arrays.toString(ABinv.coeffs));

        ReEncryptionKey rk = new ReEncryptionKey(ABinv.coeffs, params.q);
        IntegerPolynomial newCiphertext = ntruReEncrypt.reEncrypt(rk, polyCiphertext, SecureRandom.getSeed(64));
        IntegerPolynomial result = ntruReEncrypt.decrypt(keyPairB.getPrivate(), newCiphertext);
        //logger.info(Arrays.toString(result.coeffs));
        BigInteger checkResult = ntruReEncrypt.decodeMessagetoBigInteger(result, numBits);
        logger.info(checkResult.toString());

    }

}

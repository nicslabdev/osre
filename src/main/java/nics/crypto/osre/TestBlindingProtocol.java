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

        //logger.info(Arrays.toString(fA.coeffs));
        //logger.info(Arrays.toString(fB.coeffs));

        // PROBLEM: The values inside privateKey are not accessible from the outside
        //logger.info(Arrays.toString(keyPairB.getPrivate().fp.coeffs));

        IntegerPolynomial r = new IntegerPolynomial(params.N);
        for(int i = 0; i < params.N; i++) {
            r.coeffs[i] = sRNG.nextInt(params.q);
        }
        //logger.info(Arrays.toString(r.coeffs));

        IntegerPolynomial rA = r.toIntegerPolynomial().mult(fA, params.q);
        //logger.info(Arrays.toString(rA.coeffs));

        IntegerPolynomial rABinv = rA.toIntegerPolynomial().mult(fB.invertFq(params.q), params.q);
        //logger.info(Arrays.toString(rABinv.coeffs));

        IntegerPolynomial rinv = r.toIntegerPolynomial().invertFq(params.q);
        //IntegerPolynomial one = rinv.toIntegerPolynomial().mult(r, params.q);
        //logger.info(Arrays.toString(rinv.coeffs));
        //logger.info(Arrays.toString(rinv.mult(r, params.q).coeffs));
        IntegerPolynomial ABinv = rABinv.mult(r.toIntegerPolynomial().invertFq(params.q), params.q);
        //ABinv.modCenter(params.q);
        logger.info(Arrays.toString(ABinv.coeffs));

        ReEncryptionKey rk = new ReEncryptionKey(ABinv, params.q);

    }

}

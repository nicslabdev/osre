package nics.crypto.osre;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import net.sf.ntru.polynomial.IntegerPolynomial;
import nics.crypto.ntrureencrypt.NTRUReEncrypt;
import nics.crypto.ntrureencrypt.NTRUReEncryptParams;
import nics.crypto.osre.WrongParameterException;
import net.sf.ntru.encrypt.EncryptionPublicKey;

public class OSRE {

    int[] indices;
    int N;
    int degree;
    IntegerPolynomial secret;
    BigInteger mod;
    int dm0;
    String params;
    
    public OSRE(IntegerPolynomial ciphertext, int N, int degree, BigInteger mod, String params, int[] indices) throws Exception {

        if(N <= degree) {
            throw new WrongParameterException("N must be larger than the polynomial degree");
        }

        this.N = N;
        this.secret = ciphertext;
        this.mod = mod;
        this.degree = degree;
        this.indices = indices;
        this.params = params;
        this.dm0 = NTRUReEncryptParams.getDM0(params);

    }

    public OSRE(IntegerPolynomial ciphertext, int N, int degree, BigInteger mod, String params) throws Exception {

        if(N <= degree) {
            throw new WrongParameterException("N must be larger than the polynomial degree");
        }

        // By default, set the indices to {1,2,...,N}
        int[] indices = new int[N];
        for(int i = 1; i <= N; i++) {
            indices[i-1] = i;
        }

        this.N = N;
        this.secret = ciphertext;
        this.mod = mod;
        this.degree = degree;
        this.indices = indices;
        this.params = params;
        this.dm0 = NTRUReEncryptParams.getDM0(params);

    }

    /**
     * 
     * @return      A list (of length degree) of BigIntegers coefficients given a modulus
     */
    public List<BigInteger> sampleCoefficients() {

        SecureRandom sRNG = new SecureRandom();
        List<BigInteger> coefficients = new ArrayList<BigInteger>();
        
        for(int i = 0; i < this.degree; i++) {
            BigInteger sample = new BigInteger(this.mod.bitLength(), sRNG);
            while((sample.compareTo(this.mod) != -1) || (sample.compareTo(new BigInteger("0")) == 0)) {
                sample = new BigInteger(this.mod.bitLength(), sRNG);
            }
            coefficients.add(sample);
        }

        return coefficients;

    }

    /**
     * Computes the partial polynomial evaluation given an index, i.e., \sum_i (a_i * j^i)
     * 
     * @param index     The point where the polynomial is evaluated for party P_index
     * @return          The partial evaluation of the polynomial in the given index
     */
    private BigInteger computePartialPoly(int index, List<BigInteger> coefficients) {

        BigInteger result = new BigInteger("0");

        for(int i = 1; i <= this.degree; i++) {
            BigInteger exp = new BigInteger(String.valueOf(index)).pow(i);
            BigInteger product = coefficients.get(i-1).multiply(exp);
            result = result.add(product);
        }

        return result.mod(this.mod);

    }

    public IntegerPolynomial encryptPartialShare(int index, List<BigInteger> coefficients, EncryptionPublicKey deviceKey) throws Exception {

        BigInteger partialPoly = this.computePartialPoly(index, coefficients);

        NTRUReEncrypt ntruReEncrypt = new NTRUReEncrypt(NTRUReEncryptParams.getParams(this.params));

        IntegerPolynomial partialPolyEncoded = ntruReEncrypt.encodeMessage(partialPoly, SecureRandom.getSeed(5), index);
        IntegerPolynomial ciphertext = ntruReEncrypt.encrypt(deviceKey, partialPolyEncoded, SecureRandom.getSeed(5));

        ciphertext.add(this.secret);

        return ciphertext;

    }



    // Enc(a_0) + Enc(P'(j)), P'(j) = \sum_i a_i j^i

}

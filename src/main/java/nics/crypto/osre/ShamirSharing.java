package nics.crypto.osre;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class ShamirSharing {

    public static ArrayList<BigInteger> share(BigInteger secret, int N, int degree, BigInteger mod) throws Error {

        if(degree >= N){
            throw new Error("Invalid degree: cannot be >= N");
        }

        List<BigInteger> coeffs = sampleCoefficients(degree, mod);
        ArrayList<BigInteger> shares = new ArrayList<BigInteger>();
        for(int i = 1; i <= N; i++) {
            shares.add(computePartialPoly(degree, i, coeffs, mod).add(secret).mod(mod));
        }

        return shares;

    }

    /**
     * 
     * @return      A list (of length degree) of BigIntegers coefficients given a modulus
     */
    private static List<BigInteger> sampleCoefficients(int degree, BigInteger mod) {

        SecureRandom sRNG = new SecureRandom();
        List<BigInteger> coefficients = new ArrayList<BigInteger>();
        
        for(int i = 0; i < degree; i++) {
            BigInteger sample = new BigInteger(mod.bitLength(), sRNG);
            while((sample.compareTo(mod) != -1) || (sample.compareTo(new BigInteger("0")) == 0)) {
                sample = new BigInteger(mod.bitLength(), sRNG);
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
    private static BigInteger computePartialPoly(int degree, int index, List<BigInteger> coefficients, BigInteger mod) {

        BigInteger result = new BigInteger("0");

        for(int i = 1; i <= degree; i++) {
            BigInteger exp = new BigInteger(String.valueOf(index)).pow(i);
            BigInteger product = coefficients.get(i-1).multiply(exp);
            result = result.add(product);
        }

        return result.mod(mod);

    }
    
}

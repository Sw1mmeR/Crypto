using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace Crypto
{
    public class DiffieHellman
    {
        public static BigInteger P { get; private set; }
        public static BigInteger g { get; private set; }
        public static int _numberOfBytes { get; private set; }
        public BigInteger SecretKey { get; set; }
        public BigInteger PublicKey { get; private set; }
        private BigInteger CommonKey { get; set; }
        public BigInteger RecievedKey { get; set; }
        public DiffieHellman(int numberOfBytes = 16)
        {
            _numberOfBytes = numberOfBytes;
            Init();
            SecretKey = GenerateSecretKey();
            PublicKey = GeneratePublicKey();
        }
        public static void Init()
        {
            P = CryptoFunctions.GeneratePrimeNumber(_numberOfBytes);
            g = CryptoFunctions.GeneratePrimeNumber(_numberOfBytes, true);
        }
        private BigInteger GenerateSecretKey()
        {
            BigInteger secret = CryptoFunctions.GenerateRandomNumber(_numberOfBytes);
            return BigInteger.Compare(P, secret) == 1 ? secret : GenerateSecretKey();
        }
        //private BigInteger GeneratePublicKey() =>
        //Transform.MyModPow(g, SecretKey, P); // check this!
        public BigInteger GeneratePublicKey() =>
            CryptoFunctions.MyModPow(g, SecretKey, P); // check this!
        public void ApplyCommonKey()
        {
            CommonKey = CryptoFunctions.MyModPow(RecievedKey, SecretKey, P);
        }
        public void ShowStaticNumbers() =>
            Console.WriteLine($"P = {P}; g = {g}");
        public void ShowPublicKey() =>
            Console.WriteLine($"Public key = {PublicKey}");
        public void ShowSecretKey() =>
            Console.WriteLine($"Secret key = {SecretKey}");
        public void ShowCommonKey() =>
            Console.WriteLine($"Common key = {CommonKey}");
        public static void Swap(DiffieHellman A, DiffieHellman B)
        {
            A.RecievedKey = B.PublicKey;
            B.RecievedKey = A.PublicKey;
        }
    }
}

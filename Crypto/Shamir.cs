using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace Crypto
{
    public class Shamir
    {
        private static int _numberOfBytes;        
        public static BigInteger P { get; private set; }
        private BigInteger C { get; set; }
        private BigInteger D { get; set; }
        public BigInteger x1 { get; set; }
        public BigInteger x2 { get; set; }
        public BigInteger x3 { get; set; }
        public BigInteger x4 { get; set; }
        public Shamir()
        {
            C = GenerateC();
            D = CryptoFunctions.Inverse(C, P - 1);
        }
        public static void Init(int numberOfBytes = 16)
        {
            _numberOfBytes = numberOfBytes;
            P = CryptoFunctions.GenerateSimpleNumber(_numberOfBytes);
        }
        private BigInteger GenerateC()
        {
            BigInteger c = CryptoFunctions.GenerateRandomNumber(_numberOfBytes);
            return CryptoFunctions.EuclideanAlgorithm(c, P - 1) == true ? c : GenerateC();
        }
        public static BigInteger EncryptDecrypt(BigInteger message, Shamir sender, Shamir reciever)
        {
            if (message > P)
            {
                Console.WriteLine("Too big number!");
                return 0;
            }
            //Console.WriteLine($"P = {P}");
            sender.x1 = CryptoFunctions.MyModPow(message, sender.C, P);
            reciever.x1 = sender.x1;
            //Console.WriteLine($"x1 = {sender.x1}");
            reciever.x2 = CryptoFunctions.MyModPow(reciever.x1, reciever.C, P);
            sender.x2 = reciever.x2;
            //Console.WriteLine($"x2 = {sender.x2}");
            sender.x3 = CryptoFunctions.MyModPow(sender.x2, sender.D, P);
            reciever.x3 = sender.x3;
            //Console.WriteLine($"x3 = {sender.x3}");
            reciever.x4 = CryptoFunctions.MyModPow(reciever.x3, reciever.D, P);
            return reciever.x4;
        }
    }
}

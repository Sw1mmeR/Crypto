using System;
using System.Collections.Generic;
using System.Text;
using System.Numerics;
using System.Security.Cryptography;

namespace Crypto
{
    public class Elgamal
    {
        private static BigInteger k { get; set; }
        public static BigInteger P { get; set; }
        public static BigInteger G { get; set; }
        private static int _numberOfBytes;
        private BigInteger X { get; set; }
        public BigInteger Y { get; set; }
        public BigInteger RecievedY { get; set; }
        private BigInteger _sig_k;
        public Elgamal()
        {             
            k = GenK();
            X = GenK();
            Y = CryptoFunctions.MyModPow(G, X, P);
        }
        public static void Init(int numberOfBytes = 16)
        {
            _numberOfBytes = numberOfBytes;
            P = CryptoFunctions.GenerateSimpleNumber(_numberOfBytes);
            G = CryptoFunctions.GeneratePrimeNumber(_numberOfBytes, true);
        }
        public Tuple<byte[], byte[]> Encrypt(byte[] message)
        {
            BigInteger mess = new BigInteger(message);
            BigInteger a = CryptoFunctions.MyModPow(G, k, P);

            BigInteger b = BigInteger.Multiply(mess % P, CryptoFunctions.MyModPow(RecievedY, k, P)) % P;

            k = GenK();

            return Tuple.Create(a.ToByteArray(), b.ToByteArray());
        }
        public  byte[] Decrypt(Tuple<byte[], byte[]> message)
        {
            BigInteger a = new BigInteger(message.Item1);
            BigInteger b = new BigInteger(message.Item2);

            BigInteger left = b % P;
            BigInteger right = CryptoFunctions.MyModPow(a, BigInteger.Add(P, BigInteger.Negate(X)) - 1, P);

            return (BigInteger.Multiply(left, right) % P).ToByteArray();
        }
        public List<Tuple<byte[], byte[]>> EncryptList(List<byte[]> list)
        {
            var result = new List<Tuple<byte[], byte[]>>();
            foreach(var line in list)
            {                
                result.Add(Encrypt(line));
            }
            return result;
        }
        public List<byte[]> DecryptList(List<Tuple<byte[], byte[]>> list)
        {
            var result = new List<byte[]>();
            //Console.WriteLine(list[0].Length/2);

            foreach(var line in list)
            {
                result.Add(Decrypt(line));
            }
            return result;
        }
        private BigInteger GenK()
        {
            BigInteger number = CryptoFunctions.GenerateRandomNumber(_numberOfBytes);

            return number > P ? GenK() : number;
        }
        private BigInteger GenX()
        {
            BigInteger number = CryptoFunctions.GenerateRandomNumber(_numberOfBytes);

            return CryptoFunctions.ExtendedEuclideanAlgorithm(number, P-1).Item1 != 1 ? GenX() : number;
        }
        public static void Swap(Elgamal A, Elgamal B)
        {
            A.RecievedY = B.Y;
            B.RecievedY = A.Y;
        }
        private BigInteger GenerateSigK()
        {
            _sig_k = CryptoFunctions.GenerateRandomNumber(_numberOfBytes);
            return _sig_k < (P - 1) && CryptoFunctions.EuclideanAlgorithm(_sig_k, P - 1) ? _sig_k : GenerateSigK();
        }
        public byte[] ComputeSignatyre(byte[] message)
        {
            var md5 = MD5.Create();
            byte[] hash = md5.ComputeHash(message);

            BigInteger hashNumber = new BigInteger(hash);

            Console.WriteLine($"hashNumber = {hashNumber} ({hash.Length}), p = {P} ({P.ToByteArray().Length})\n");

            if(hashNumber.Sign == -1)
            {
                hashNumber = BigInteger.Negate(hashNumber);
            }
            GenerateSigK();

            BigInteger r = CryptoFunctions.MyModPow(G, _sig_k, P);
            BigInteger hmodp = hashNumber % (P - 1);
            BigInteger xr = BigInteger.Multiply(X, r) % (P - 1);
            BigInteger u = BigInteger.Add(hmodp, BigInteger.Negate(xr)) % (P - 1);
            BigInteger s = BigInteger.Multiply(CryptoFunctions.Inverse(_sig_k, P - 1), u) % (P - 1);

            byte[] r_bytes = r.ToByteArray();
            byte[] s_bytes = s.ToByteArray();

            Console.WriteLine($"Not encrypted hash: {hashNumber}, Length = {hash.Length}\n");
            Console.WriteLine($"Encrypted hash: {r} ({r_bytes.Length}), {s} ({s_bytes.Length})\n");

            byte[] sig = new byte[message.Length + r_bytes.Length + s_bytes.Length];

            message.CopyTo(sig, 0);
            r_bytes.CopyTo(sig, message.Length);
            s_bytes.CopyTo(sig, message.Length + r_bytes.Length);
            
            Console.WriteLine($"Encrypted hash: {Convert.ToBase64String(sig)}\n");

            //Console.WriteLine(BigInteger.Multiply(CryptoFunctions.MyModPow(Y, r, P), CryptoFunctions.MyModPow(r, s, P)) % P);
            //Console.WriteLine(CryptoFunctions.MyModPow(G, hashNumber, P));
            return sig;
        }
        public bool CheckSignature(byte[] sig)
        {
            byte[] message = new byte[sig.Length - _numberOfBytes * 2];
            byte[] r_bytes = new byte[_numberOfBytes];
            byte[] s_bytes = new byte[_numberOfBytes];
            
            Array.Copy(sig, message.Length, r_bytes, 0, r_bytes.Length);
            Array.Copy(sig, message.Length + r_bytes.Length, s_bytes, 0, s_bytes.Length);
            Array.Copy(sig, 0, message, 0, sig.Length - _numberOfBytes * 2);

            BigInteger r = new BigInteger(r_bytes);
            BigInteger s = new BigInteger(s_bytes);
            
            Console.WriteLine($"Recieved hash: {Convert.ToBase64String(r_bytes)}, {Convert.ToBase64String(s_bytes)}, Length = {r_bytes.Length}, {s_bytes.Length}\n");
            
            var md5 = MD5.Create();
            byte[] hash = md5.ComputeHash(message);
            BigInteger hashNumber = new BigInteger(hash);
            if (hashNumber.Sign == -1)
            {
                hashNumber = BigInteger.Negate(hashNumber);
            }

            var c1 = CryptoFunctions.MyModPow(RecievedY, r, P);
            var c2 = CryptoFunctions.MyModPow(r, s, P);

            Console.WriteLine($"c1 = {c1}, c2 = {c2}");
            Console.WriteLine($"G = {G}, P = {P}");
            
            Console.WriteLine($"\nc1 * c2 % P: {BigInteger.Multiply(c1, c2) % P}");
            Console.WriteLine($"ModPow(G, hash, P): {CryptoFunctions.MyModPow(G, hashNumber, P)}\n");

            if (BigInteger.Compare((BigInteger.Multiply(c1, c2) % P), CryptoFunctions.MyModPow(G, hashNumber, P)) == 0)
                return true;
            else
                return false;
        }
        /*public bool CheckSignature(byte[] sig, string writing_path = "")
        {
            byte[] message = new byte[sig.Length - _numberOfBytes * 2];
            byte[] hashPart = new byte[_numberOfBytes * 2];

            Array.Copy(sig, 0, message, 0, message.Length);
            Array.Copy(sig, message.Length, hashPart, 0, hashPart.Length);

            if (writing_path != "")
                File.WriteAllBytes(writing_path, message);


            var md5 = MD5.Create();
            byte[] hash = md5.ComputeHash(message);

            var decoed = CryptoFunctions.MyModPow(new BigInteger(hashPart), PublicKey.Item1, PublicKey.Item2);

            Console.WriteLine($"Decrypted hash: {Convert.ToBase64String(decoed.ToByteArray())}\n");

            if (new BigInteger(hash) == decoed)
                return true;
            else
                return false;
        }*/
    }
}

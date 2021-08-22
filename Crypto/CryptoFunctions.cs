using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Crypto
{
    public static class CryptoFunctions
    {
        // Статический объект класса Random для генерации псевдослучайных байтов
        static Random rnd = new Random();
        // Быстрое возведение в степень по модулю
        public static BigInteger MyModPow(BigInteger value, BigInteger exponent, BigInteger modulus)
        {
            BigInteger composition = 1;
            while (exponent > 0)
            {
                if((exponent & 1) == 1)
                {
                    composition = (composition * value) % modulus;
                }
                value = (value * value) % modulus;
                exponent >>= 1;
            }
            return composition;
        }
        // НОД (Если НОД 2х чисел == 1, то эти числа взаимно простые)
        public static bool EuclideanAlgorithm(BigInteger a, BigInteger b) 
        {
            if (a % b == 0)
                return false;
            while (a != 0 && b != 0)
            {
                if (a > b)
                    a %= b;
                else
                    b %= a;
            }
            if (a + b == 1)
                return true;
            else
                return false;
        }
        // Обопщенный алгоритм Евклида int
        public static Tuple<int, int, int> ExtendedEuclideanAlgorithm(int a, int b)
        {
            var u = Tuple.Create(a, 1, 0);
            var v = Tuple.Create(b, 0, 1);
            int q;
            while (v.Item1 != 0)
            {
                q = u.Item1 / v.Item1;
                var t = Tuple.Create(u.Item1 % v.Item1, u.Item2 - q * v.Item2, u.Item3 - q * v.Item3);
                u = v;
                v = t;
            }
            return u;
        }
        // Обопщенный алгоритм Евклида BigInteger
        public static Tuple<BigInteger, BigInteger, BigInteger> ExtendedEuclideanAlgorithm(BigInteger a, BigInteger b) // need make rec
        {
            BigInteger x = 1, y = 0;
            var u = Tuple.Create(a, x, y);
            var v = Tuple.Create(b, y, x);
            BigInteger q;
            while (v.Item1 != 0)
            {
                q = u.Item1 / v.Item1;
                var t = Tuple.Create(u.Item1 % v.Item1, u.Item2 - q * v.Item2, u.Item3 - q * v.Item3);
                u = v;
                v = t;
            }
            return u;
        }
        // Инверсия числа
        public static BigInteger Inverse(BigInteger c, BigInteger m)
        {
            BigInteger x = 1, y = 0;
            var u = Tuple.Create(m, y);
            var v = Tuple.Create(c, x);
            BigInteger q;
            while (v.Item1 != 0)
            {
                q = u.Item1 / v.Item1;
                var t = Tuple.Create(u.Item1 % v.Item1, u.Item2 - q * v.Item2);
                u = v;
                v = t;
            }
            return u.Item2 < 0 ? u.Item2 + m : u.Item2;
        }
        // Тест Ферма на простоту
        public static bool FermatsTest(BigInteger number)
        {
            if (number == 2) return true;
            Random rnd = new Random();
            BigInteger a = rnd.Next(2, 1000);

            return MyModPow(a, number - 1, number) == 1 ? true : false;
        }
        // Тест Миллера Рабина на простоту
        public static bool MillerRabinTest(BigInteger n, int k = 100) // k-количетсво итераций цикла проверки
        {
            if (n == 2 || n == 3)
                return true;
            if (n % 2 == 0) // Если число четное, то оно точно составное
                return false;

            BigInteger number = n - 1;
            int degree = 0; // s (показатель двойки)
            while (number % 2 == 0) // После выполнения number(t) содержит нечетный множитель при разложении 2^s * t
            {
                number /= 2;
                ++degree;
            }
            for (int i = 0; i < k; ++i)
            {
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

                byte[] _a = new byte[n.ToByteArray().LongLength];
                BigInteger a;

                do // Случайное число в отрезке[2, n - 2]
                {
                    rng.GetBytes(_a);
                    a = new BigInteger(_a);
                } while (a < 2 || a > n - 2);

                BigInteger x = MyModPow(a, number, n);
                if (x == 1 || x == n - 1)
                    continue;
                for (int j = 0; j < degree - 1; ++j)
                {
                    x = (x * x) % n;
                    if (x == 1)
                        return false;
                    if (x == n - 1)
                        break;
                }
                if (x != n - 1)
                    return false;
            }
            return true;
        }
        // Генератор случайного числа
        public static BigInteger GenerateRandomNumber(int numberOfBytes = 10)
        {
            byte[] bytes = new byte[numberOfBytes];
            rnd.NextBytes(bytes);
            BigInteger result = new BigInteger(bytes);
            return result < 0 ? BigInteger.Negate(result) : result;
        }
        // Генератор простого случайного числа
        public static BigInteger GenerateSimpleNumber(int numberOfBytes = 10)
        {
            BigInteger number = GenerateRandomNumber(numberOfBytes);
            bool isSimple = false;
            number = GenerateRandomNumber(numberOfBytes);
            isSimple = MillerRabinTest(number, 100);

            return isSimple == true ? number : GenerateSimpleNumber(numberOfBytes);
        }
        // Генератор простого p = 2q + 1, генератор g
        public static BigInteger GeneratePrimeNumber(int numberOfBytes = 10, bool generator = false)
        {
            BigInteger Q = GenerateSimpleNumber(numberOfBytes);
            BigInteger prime = BigInteger.Multiply(Q, 2) + 1;

            if (generator)
            {
                BigInteger gen = GenerateRandomNumber(numberOfBytes - 1);

                //Console.WriteLine($"Prime = {prime}; Q = {Q}; Gen = {gen}");

                return (gen < BigInteger.Add(prime, -1)) && MyModPow(gen, Q, prime) != 1 ? gen : GeneratePrimeNumber(numberOfBytes, generator);
            }
            else
            {
                //Console.WriteLine($"Prime = {prime}; Q = {Q}");
            }
            return MillerRabinTest(prime) ? prime : GeneratePrimeNumber(numberOfBytes);
        }
        // Запись байтов в виде файла
        public static int SetFileBytes(string path, List<byte[]> list, int numberOfBytes = 32)
        {
            int length = 0, step = 0;
            for (int i = 0; i < list.Count; ++i)
            {
                if(list[i].Length < numberOfBytes && i != list.Count - 1)
                {
                    BigInteger big = new BigInteger(list[i]);

                    byte[] addedZeroes = new byte[numberOfBytes];
                    list[i].CopyTo(addedZeroes, 0);
                    if (BigInteger.Compare(big, 0) == -1)
                    {
                        addedZeroes[addedZeroes.Length - 1] = 255;
                    }
                    list[i] = addedZeroes;
                }
                length += list[i].Length;
            }

            byte[] res = new byte[length];
            //Console.WriteLine($"Writed: {res.Length} bytes");

            for (int i = 0; i < list.Count; ++i)
            {
                byte[] buffer = new byte[list[i].Length];
                list[i].CopyTo(buffer, 0);

                buffer.CopyTo(res, step);
                step += list[i].Length;
            }
            File.WriteAllBytes(path, res);
            return res.Length;
        }
        public static List<byte[]> ReadFileBytes(string path, int numberOfBytes = 32)
        {
            List<byte[]> result = new List<byte[]>();
            byte[] fileBytes = File.ReadAllBytes(path);

            //Console.WriteLine($"Readed: {fileBytes.Length} bytes");

            int step = 0;
            int lastStep = fileBytes.Length % numberOfBytes;            

            for (int i = 0; i < fileBytes.Length / numberOfBytes; ++i)
            {
                byte[] buffer = new byte[numberOfBytes];
                Array.Copy(fileBytes, 0 + step, buffer, 0, numberOfBytes);
                result.Add(buffer);
                step += numberOfBytes;
            }
            if (lastStep != 0)
            {
                byte[] buffer2 = new byte[lastStep];
                Array.Copy(fileBytes, fileBytes.Length - lastStep, buffer2, 0, lastStep);
                result.Add(buffer2);
            }
            return result;
        }
    }
}
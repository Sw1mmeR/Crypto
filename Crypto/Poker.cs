using System;
using System.Collections.Generic;
using System.Text;
using System.Numerics;

namespace Crypto
{
    public class Poker
    {
        private static string[] deckValue = { "2К", "2П", "2Б", "2Ч",
                                              "3К", "3П", "3Б", "3Ч",
                                              "4К", "4П", "4Б", "4Ч",
                                              "5К", "5П", "5Б", "5Ч",
                                              "6К", "6П", "6Б", "6Ч",
                                              "7К", "7П", "7Б", "7Ч",
                                              "8К", "8П", "8Б", "8Ч",
                                              "9К", "9П", "9Б", "9Ч",
                                              "10К", "10П", "10Б", "10Ч",
                                              "ВК", "ВП", "ВБ", "ВЧ",
                                              "ДК", "ДП", "ДБ", "ДЧ",
                                              "КК", "КП", "КБ", "КЧ",
                                              "ТК", "ТП", "ТБ", "ТЧ", };
        public static List<BigInteger> _deck;
        private static BigInteger P;
        public static int _players;
        
        public static Tuple<BigInteger, BigInteger> CreatePlayer()
        {
            BigInteger c, d;
            do
            {
                c = CryptoFunctions.GenerateRandomNumber(4);
                d = CryptoFunctions.Inverse(c, P - 1);
            } while (BigInteger.Multiply(c, d) % (P - 1) != 1);

            //Console.WriteLine(BigInteger.Multiply(c, d) % (P - 1));

            return Tuple.Create(c, d);
        }
        public static void Init(int players = 3)
        {
            CreateDeck();
            _players = players;
            P = CryptoFunctions.GeneratePrimeNumber(6);
        }
        public static void CreateDeck(int cards = 52)
        {
            var deck = new List<BigInteger>();

            for(int i = 0; i < cards; ++i)
            {
                //CryptoFunctions.GenerateRandomNumber(4)
                deck.Add(i + 2); 
                //Console.WriteLine($"{i}) {deck[i]}");
            }
            _deck = deck;
        }
        public static void Shuffle(List<BigInteger> deckToShuffle)
        {
            Random rand = new Random();

            for (int i = deckToShuffle.Count - 1; i >= 1; i--)
            {
                int j = rand.Next(i + 1);

                var buffer = deckToShuffle[j];
                deckToShuffle[j] = deckToShuffle[i];
                deckToShuffle[i] = buffer;
            }
        }
        public static void ShowDeck(bool isStr = false, Tuple<BigInteger, BigInteger> cardsOnHand = null)
        {
            if (isStr)
            {
                List<BigInteger> deck = null;
                if (cardsOnHand != null)
                {
                    deck = new List<BigInteger>();
                    deck.Add(cardsOnHand.Item1);
                    deck.Add(cardsOnHand.Item2);
                }
                else
                {
                    deck = _deck;
                }
                for (int i = 0; i < deck.Count; ++i)
                {
                    for (int j = 0; j < _deck.Count; ++j)
                    {
                        if (deck[i] - 2 == j)
                        {
                            if (deckValue[j][deckValue[j].Length - 1].ToString() == "К" || deckValue[j][deckValue[j].Length - 1].ToString() == "П")
                                Console.ForegroundColor = ConsoleColor.Gray;
                            else
                                Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"{i}) {deckValue[j]}");
                            Console.ForegroundColor = ConsoleColor.Green;
                        }
                    }
                }
            }
            else
            {
                for (int i = 0; i < _deck.Count; ++i)
                {
                    Console.WriteLine($"{i}) {_deck[i]}");
                }
            }
        }
        
        public static List<BigInteger> EncryptDeck(Tuple<BigInteger, BigInteger> tuple, List<BigInteger> deckToEncrypt)
        {
            Shuffle(deckToEncrypt);
            var result = new List<BigInteger>();

            for (int i = 0; i < deckToEncrypt.Count; ++i)
            {
                result.Insert(i, CryptoFunctions.MyModPow(deckToEncrypt[i], tuple.Item1, P));
            }
            _deck = result;
            return result;
        }
        public static Tuple<BigInteger, BigInteger> DecryptCards(Tuple<BigInteger, BigInteger> cards, BigInteger D)
            => Tuple.Create(CryptoFunctions.MyModPow(cards.Item1, D, P),
                CryptoFunctions.MyModPow(cards.Item2, D, P));
        public static List<Tuple<BigInteger, BigInteger>> CreatePlayers(int numberOfPlayers = 2)
        {
            var list = new List<Tuple<BigInteger, BigInteger>>();
            for(int i = 0; i < numberOfPlayers; ++i)
            {
                list.Add(CreatePlayer());
            }
            return list;
        }
        public static List<Tuple<BigInteger, BigInteger>> Distrib(int numberOfPlayers)
        {
            var result = new List<Tuple<BigInteger, BigInteger>>();
            int step = 0;
            //result.Add(tuple);
            for (int i = 0; i < numberOfPlayers; i++)
            {
                for (int j = 0; j < 2; ++j)
                {
                    var tuple = Tuple.Create(_deck[j + step], _deck[j + 1 + step]);
                    if(j % 2 == 0)
                        result.Add(tuple);              
                }
                step += 2;
            }
            return result;
        }
    }
}

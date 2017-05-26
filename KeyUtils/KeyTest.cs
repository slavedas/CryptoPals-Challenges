using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using CryptoChallenge;
using XORFunctions;

namespace KeyUtils
{
    public class Hamming
    {
        public static  int CalculateHammingDistancePlain(string plaintext1, string plaintext2)
        {
            return CalculateHammingDistance(ASCIIEncoding.ASCII.GetBytes(plaintext1), ASCIIEncoding.ASCII.GetBytes(plaintext2));
        }
        public static int CalculateHammingDistanceHex(string hexString1, string hexString2)
        {
            return CalculateHammingDistance(StringBaseConversion.HexStringToByteArray(hexString1), StringBaseConversion.HexStringToByteArray(hexString2));
        }

        public static int CalculateHammingDistance(byte [] lhs, byte [] rhs)
        {
            if (lhs.Length != rhs.Length)
            {
                throw new ArgumentOutOfRangeException("Length of both arguments must be equal.");
            }
            int count = 0;
            for (int ii=0; ii < lhs.Length; ++ii)
            {
                var value = lhs[ii] ^ rhs[ii];
                
                while (value > 0)
                {
                    count += value % 2;
                    value >>= 1;
                }
            }
            return count;
        }

        public static int FindHammingMatch(byte[] cipherText, byte[] block)
        {
            byte[] cipherBlock = new byte[block.Length];
            for (int ii = 0; ii < cipherText.Length - block.Length; ii += block.Length)
            {
                System.Buffer.BlockCopy(cipherText, ii, cipherBlock, 0, cipherBlock.Length);
                if (Hamming.CalculateHammingDistance(block, cipherBlock) == 0)
                {
                    return ii;
                }
            }
            return -1;
        }
    }

    public class KeyTools
    {
        public static int[] FindMostLikelyKeysize(byte [] cipherBytes, int minKeyLength=2, int maxKeyLength=40, int keysizesToReturn=1)
        {
            var result = new int[keysizesToReturn];
            var keySizeDictionary = new Dictionary<int, double>();
            for (int ks = minKeyLength; ks <= maxKeyLength; ++ks)
            {
                var block1 = new byte[ks];
                var block2 = new byte[ks];
                Array.Copy(cipherBytes, block1, ks);
                int count = 0;
                keySizeDictionary[ks] = 0;
                for (int ii = ks; ii < cipherBytes.Length - ks; ii += ks)
                {
                    Array.Copy(cipherBytes, ii, block2, 0, ks);
                    keySizeDictionary[ks] += Hamming.CalculateHammingDistance(block1, block2);
                    block2.CopyTo(block1, 0);
                    ++count;
                }
                keySizeDictionary[ks] /= (count * ks);
            }
            var sorted = keySizeDictionary.OrderBy(x => x.Value).ToArray();
            for (int ii = 0; ii < keysizesToReturn; ++ii)
            {
                result[ii] = sorted[ii].Key;
            }
            return result;

        }

        public static byte[][] KeysizeByteTranspose(byte [] cipherText, int keysize)
        {
            byte[][] result = new byte[keysize][];
            for (int ii = 0; ii < keysize; ++ii)
            {
                result[ii] = new byte[cipherText.Length / keysize + 1];
            }
            int count = 0;
            for (int ii = 0; ii < cipherText.Length; ++ii)
            {
                var mod = ii % keysize;
                result[mod][count] = cipherText[ii];
                if (mod == keysize - 1)
                {
                    count += 1;
                }
            }
            return result;
        }
    }
    public class KeyTest
    {
        public static void FindRepeatingKeyTest(byte [] input = null, int input_keysize=0)
        {
            byte[] rawBytes = input;
            if (rawBytes == null)
            {
                FileStream fs = new FileStream("C:/Users/stephen.lavedas/Downloads/CryptoChallenge6.txt", FileMode.Open);
                BinaryReader fin = new BinaryReader(fs);
                var fileBytes = fin.ReadChars((int)fin.BaseStream.Length);
                rawBytes = Convert.FromBase64CharArray(fileBytes, 0, fileBytes.Length);
            }
            int[] mostLikelyKeysizes = null;
            if (input_keysize == 0)
            {
                 mostLikelyKeysizes = KeyTools.FindMostLikelyKeysize(rawBytes, keysizesToReturn: 4);
            }
            else
            {
                mostLikelyKeysizes = new int[1];
                mostLikelyKeysizes[0] = input_keysize;
            }
            byte[][] decipherResults = new byte[mostLikelyKeysizes.Length][];
            byte[][] keys = new byte[mostLikelyKeysizes.Length][];
            for (int ii = 0; ii < mostLikelyKeysizes.Length; ++ii)
            {
                var keysize = mostLikelyKeysizes[ii];
                var keyByteArrays = KeyTools.KeysizeByteTranspose(rawBytes, keysize);
                byte[] key = new byte[keysize];
                int keycount = 0;
                ByteArrayXOR.m_PrintDebug = false;
                /*
                System.Console.WriteLine("\n\n\n--------------------------------------------------------------------------------\n");
                System.Console.WriteLine("                                        Key Length: " + keysize + "                         \n");
                System.Console.WriteLine("--------------------------------------------------------------------------------\n\n\n");
                */
                foreach (var keyByteArray in keyByteArrays)
                {
                    var result = ByteArrayXOR.FindBestSingleXORKey(keyByteArray);
                    key[keycount++] = result.Item1;
                }
                System.Console.WriteLine("XORKey Length: " + keysize + " Possibly: " + ASCIIEncoding.ASCII.GetString(key));
                decipherResults[ii] = ByteArrayXOR.RepeatedXOR(key, rawBytes);
                keys[ii] = key;
            }
            int maxScore = 0;
            int maxScoreIndex = 0;
            for (int ii = 0; ii < decipherResults.Length; ++ii)
            {
                var score = ByteArrayXOR.ScorePlainText(decipherResults[ii]);
                if (score > maxScore)
                {
                    maxScore = score;
                    maxScoreIndex = ii;
                }
            }
            System.Console.WriteLine("Best Key: " + ASCIIEncoding.ASCII.GetString(keys[maxScoreIndex]) + " Length: " + keys[maxScoreIndex].Length);
            System.Console.WriteLine("Message: " + ASCIIEncoding.ASCII.GetString(decipherResults[maxScoreIndex]));
        }

        static void Main(string[] args)
        {
            var count = Hamming.CalculateHammingDistancePlain("this is a test", "wokka wokka!!!");
            Console.WriteLine("The hamming distance is " + count);
            FindRepeatingKeyTest();

        }
    }
}

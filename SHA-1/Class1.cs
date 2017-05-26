using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SHA_1
{
    public class SHA1Impl
    {
        public static string byteArrayToString(byte[] input)
        {
            string tempst = "";

            for (int i = 0; i < input.Length; i++)
                tempst += input[i].ToString("X2");
            return tempst;
        }

        public static string uintArrayToString(uint[] input)
        {
            string result = "";
            for (int i = 0; i < input.Length; i++)
            {
                uint high = input[i] >> 24;
                uint midhigh = (input[i] << 8) >> 24;
                uint midlow = (input[i] << 16) >> 24;
                uint low = (input[i] << 24) >> 24;
                result += high.ToString("X2") + midhigh.ToString("X2") + midlow.ToString("X2") + low.ToString("X2");
            }
            return result;
        }
        public static byte[] padInput(byte[] input)
        {
            uint bytesToPad = Convert.ToUInt32(64 - (input.Length % 64));
            if (bytesToPad < 8)
            {
                bytesToPad = 64;
            }
            byte[] paddedInput = new byte[input.Length + bytesToPad];
            Buffer.BlockCopy(input, 0, paddedInput, 0, input.Length);
            paddedInput[input.Length] = 0x80;

            //Input is padded to 512-bit block size
            //Now to add the actual SHA1 computation code.
            UInt64 length = (UInt64)input.Length * 8; //Length in bits
            var lenBytes = BitConverter.GetBytes(length);
            lenBytes = lenBytes.Reverse().ToArray();
            Buffer.BlockCopy(lenBytes, 0, paddedInput, paddedInput.Length - 8, 8);
            return paddedInput;
        }

        public static byte getByte(uint x, int n)
        {
            return (byte)((x >> 8 * n) & 0xFF);
        }

        public static uint circularShift(int bits, uint word)
        {
            uint output = (word << bits | word >> (32 - bits));
            return output;
        }

        public static void process(byte[] source, uint[] hash=null)
        {
            if (hash == null)
            {
                hash = new uint[] { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
            }
            var paddedSource = padInput(source);
            uint[] block = new uint[16];
            for (int ii = 0; ii < paddedSource.Length; ii += 64)
            {
                Buffer.BlockCopy(paddedSource, ii, block, 0, 64);
                for (int jj = 0; jj < block.Length; ++jj)
                {
                    block[jj] = BitConverter.ToUInt32((BitConverter.GetBytes(block[jj]).Reverse().ToArray()), 0);
                }
                processBlock(block, hash);
            }
        }

        /// <summary>
        /// This is Method 1 from http://www.faqs.org/rfcs/rfc3174.html wherein the original 16 words are first used to populate an 80 word array.
        /// 
        /// </summary>
        /// <param name="block">This should be the 16 word message</param>
        /// <param name="hash">This is a H0 through H4 in the RFC3174 spec. Initial values should be  0x67452301, 0xEFCDAB89,0x98badcfe,0x10325476,0xc3d2e1f0 </param>
        /// <param name="bigarray">This should be an 80 word array</param>
        public static void processBlock(uint[] block, uint[] hash)
        {
            uint[] bigarray = new uint[80];
            uint temp = 0;
            const uint k0 = 0x5a827999;
            const uint k1 = 0x6ed9eba1;
            const uint k2 = 0x8f1bbcdc;
            const uint k3 = 0xca62c1d6;
            int t = 0;
            for (t = 0; t < 16; t++)
            {
                bigarray[t] = block[t];
            }

            for (t = 16; t < 80; t++)
            {
                bigarray[t] = circularShift(1, (bigarray[t - 3] ^ bigarray[t - 8] ^ bigarray[t - 14] ^ bigarray[t - 16]));
            }

            uint A = hash[0];
            uint B = hash[1];
            uint C = hash[2];
            uint D = hash[3];
            uint E = hash[4];

            for (t = 0; t < 20; t++)
            {
                temp = circularShift(5, A) + ((B & C) | ((~B) & D)) + E + bigarray[t] + k0;
                E = D;
                D = C;
                C = circularShift(30, B);
                B = A;
                A = temp;
            }

            for (t = 20; t < 40; t++)
            {
                temp = circularShift(5, A) + (B ^ C ^ D) + E + bigarray[t] + k1;
                E = D;
                D = C;
                C = circularShift(30, B);
                B = A;
                A = temp;
            }

            for (t = 40; t < 60; t++)
            {
                temp = circularShift(5, A) + ((B & C) | (B & D) | (C & D)) + E + bigarray[t] + k2;
                E = D;
                D = C;
                C = circularShift(30, B);
                B = A;
                A = temp;
            }

            for (t = 60; t < 80; t++)
            {
                temp = circularShift(5, A) + (B ^ C ^ D) + E + bigarray[t] + k3;
                E = D;
                D = C;
                C = circularShift(30, B);
                B = A;
                A = temp;
            }


            hash[0] += A;
            hash[1] += B;
            hash[2] += C;
            hash[3] += D;
            hash[4] += E;

        }
    }
}

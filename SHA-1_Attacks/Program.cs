using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SHA_1;
using System.Security.Cryptography;

namespace SHA_1_Attacks
{
    class Program
    {
        static void Main(string[] args)
        {

            //byte[] byteblock = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };
            var byteblock = Encoding.ASCII.GetBytes("The quick brown fox jumps over the lazy dog.  The dog didn't even look up it was so lazy.  There has never been a lazier dog in all of time or space.");
            Console.WriteLine("Starting array");
            Console.WriteLine(SHA1Impl.byteArrayToString(byteblock));

            uint[] bigpadded = new uint[80];
            SHA1 hasher = SHA1CryptoServiceProvider.Create();

            byte[] hashByCPU = (byte[])hasher.ComputeHash(byteblock, 0, byteblock.Length);

            uint[] hashByGPU = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
            SHA1Impl.process(byteblock, hashByGPU);
            Console.WriteLine("Correct hash:" + SHA1Impl.byteArrayToString(hashByCPU) + " which is " + hashByCPU.Length.ToString() + " bytes long");
            Console.WriteLine("Hash by fGPU:" + SHA1Impl.uintArrayToString(hashByGPU) + " which is " + hashByGPU.Length.ToString() + " words long");


        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            //throw new NotImplementedException();

            int myResult;

            int A1 = 1, A2 = 0, A3 = baseN;
            int B1 = 0, B2 = 1, B3 = number;
            int Q = 0;

            int New_A1 = 0, New_A2 = 0, New_A3 = 0;
            int New_B1 = 0, New_B2 = 0, New_B3 = 0;

            while (B3 != 1)
            {

                /*Console.Write(Q + "   " + A1 + " " + A2 + " " + A3);
                Console.WriteLine("     " + B1 + " " + B2 + " " + B3);*/

                Q = A3 / B3;

                New_A1 = B1;
                New_A2 = B2;
                New_A3 = B3;

                New_B1 = A1 - Q * B1;
                New_B2 = A2 - Q * B2;
                New_B3 = A3 - Q * B3;

                /*Console.Write(Q + "   " + New_A1 + " " + New_A2 + " " + New_A3);
                Console.WriteLine("     " + New_B1 + " " + New_B2 + " " + New_B3);*/

                A1 = New_A1; A2 = New_A2; A3 = New_A3;
                B1 = New_B1; B2 = New_B2; B3 = New_B3;

                if (New_B3 == 0) { myResult = -1; break; }
                else
                {
                    Q = New_A3 / New_B3;
                }

            }

            //Console.WriteLine(B2);

            if (New_B3 != 0)
            {
                while (B2 < 0)
                {
                    B2 = B2 + 26;
                }

                myResult = B2;
                return myResult;
            }
            else { myResult = -1; return myResult; }

            /*
            Console.WriteLine(myResult);
            Console.WriteLine(myResult == result);*/


        }
    }
}

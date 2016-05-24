// File Name: des.cpp
// Author: Benjamin Wilfong
// Date Submitted: 5/5/2016
// Program Description: This program handles encryption and decryption via DES and an 8-byte key.
//                      The user must specify an encryption/decryption flag, the 8-byte key,
//                      an input file and an output file as command line arguments.
//                      Although some of the methods could have been combined (some simply use
//                      a table of a certain size to permute a data block of a certain size) I
//                      thought it would be better to write a function that performed a single
//                      piece for every step of the way. There are debugging statements commented
//                      out at each step. I wrote a function to output a block with a given # of bits 
//                      if anything does not work correctly and you would like to see what is happening
//                      in binary. Other than that, if one understands the steps of DES encryption/decryption,
//                      it is easy to read through the code and see what is happening.

#include <iostream>
#include <string.h>
#include <fstream>

using namespace std;

string initialPermutation(string);
string keyPermutation(string);
string shiftKey(string,int,int);
string compressionPermutation(string);
string expansionPermutation(string);
string xorTheKeyAndData(string,string);
string sBoxPermutation(string,const int[8][4][16]);
string pBoxPermutation(string);
string xorLeftHalf(string,string);
string switchHalves(string);
string finalPermutation(string);
int getRowIndex(int,int);
int getColIndex(int,int,int,int);
string getZeroString(int);
int getBit(int,string);
void putBit(int,int,string&);
void writeToFile(string,string);
string getFileText(string);
void outputKey(string);
void outputBits(string,int);


int main(int argc, char** argv)
{

     const int sBoxTables[8][4][16] = {{{14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
                                        { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
                                        { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
                                        {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}},  // end s-box 1
                    
                                       {{15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
                                        { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
                                        { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
                                        {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}},  // end s-box 2

                                       {{10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
                                        {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
                                        {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
                                        { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}},  // end s-box 3

                                       {{ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
                                        {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
                                        {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
                                        { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}},  // end s-box 4

                                       {{ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
                                        {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
                                        { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
                                        {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}},  // end s-box 5  

                                       {{12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
                                        {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
                                        { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
                                        { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}},  // end s-box 6

                                       {{ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
                                        {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
                                        { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
                                        { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}},  // end s-box 7

                                       {{13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
                                        { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
                                        { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
                                        { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}}}; // end s-sbox 8
     
//==========================================================================================================================
//end s-table declaration

     int mode; // used for signifying en/decryption
     int padding; // used to make the input string an even multiple of 8
     int numRounds; // number of blocks will be needed to transform

// Command line handling ============================================================================

     if (argc != 5)
     {
          cout << "Invalid command line arguments." << endl;
          cout << "Please use the form: des [-d|-e] [key] [input file] [output file]" << endl;
          return 0; 
     }

     if (strlen(argv[2]) != 8)
     {
          cout << "Invalid key length. The key must be an 8-character string" << endl;
          return 0;
     }

     if (strcmp(argv[1], "-e") == 0)
          mode = 0; // encryption mode

     else if (strcmp(argv[1], "-d") == 0)
          mode = 1; // decryption mode

     else
     {
          cout << "Invalid encryption/decryption flag." << endl;
          cout << "Please use the form: des [-d|-e] [key] [input file] [output file]" << endl;
          return 0;
     }

// End command line handling ========================================================================

     string text = getFileText(argv[3]);

     string key = argv[2];

     string tempText, tempKey, compressedKey, expandedData, 
            sBoxData, finalPermutedData, changedText; // placeholders for blocks

     cout << "Input Text:\n" << text << endl;

     //cout << text.length() << endl;

     if(text.length() % 8 != 0)
          padding = 8 - (text.length() % 8); // the amount of chars needed to be
                                                   // divisible by 8.
     else
          padding = 0; // the above formula will add 8 0's if its divisible by 8, not needed


     for (int i = 0; i < padding; i++)
          text += "0"; // pad the string to make it an even multiple of 8
     
     changedText = getZeroString(text.length()); // placeholder for permuted text
     
     numRounds = text.length() / 8;

     //cout << text.length() << endl;

     for (int i = 0; i < numRounds; i++) // start the transformation
     {
          tempText = text.substr(i * 8, 8); // get a 64-bit block into temp
 
          //cout << tempText << endl;            

          //cout << "Binary representation of input: ";  outputBits(tempText, tempText.size() * 8);
          finalPermutedData = initialPermutation(tempText);


          tempKey = keyPermutation(key);

          //cout << "Initial Key: "; outputKey(tempKey);
          
          for(int j = 0; j < 16; j++) // do the 16 rounds
          {   
               if(mode == 0)//{
                    tempKey = shiftKey(tempKey, j, mode); // pass the 56-bit key to split and shift and
                                                          // pass the round number for the # of shifts

                    //cout << "Key #" << j + 1 << ": "; outputKey(tempKey);}
               else//{
                    if( j != 0) // don't shift the first round. K16 is always the initial key, which we already
                                // have the first round. Start shifting after the first round.
                         tempKey = shiftKey(tempKey,16 - j, mode); // do the shifts in reverse if decrypting
                    //cout << "Key #" << 16 - j << ": "; outputKey(tempKey);}
               //outputKey(tempKey);

               compressedKey = compressionPermutation(tempKey);

               expandedData = expansionPermutation(finalPermutedData);

               //cout << "Expanded Data: "; outputBits(expandedData, 48);

               sBoxData = xorTheKeyAndData(compressedKey, expandedData);

               //cout << "Data after XOR1: "; outputBits(sBoxData, 48);

               sBoxData = sBoxPermutation(sBoxData, sBoxTables);

               //cout << "Sbox Data: "; outputBits(sBoxData, 32);

               sBoxData = pBoxPermutation(sBoxData);

               //cout << "pBox Data: "; outputBits(sBoxData, 32);

               finalPermutedData = xorLeftHalf(finalPermutedData, sBoxData);
                   // This will xor the left half of the data after the
                   // initial permutation with the results from the pbox perm.

               //cout << "Data after XOR2: "; outputBits(finalPermutedData, 64);
               
               if( j != 15) // don't switch the final round (0 being the first)   
                    finalPermutedData = switchHalves(finalPermutedData);              

               //cout << "Data after Switch: "; outputBits(finalPermutedData, 64);
          }
                  
         finalPermutedData = finalPermutation(finalPermutedData);
         //cout << "Data after Final Permutation: "; outputBits(finalPermutedData, 64);

         for(int m = 0; m < 8; m++)
            changedText.at((i * 8) + m) = finalPermutedData.at(m); // append the block to the 
                                                                   // the entire 

         //cout << "END BLOCK================================================" << endl;      
     }

     //cout << changedText.length() << endl;

     cout << "Output Text:\n" << changedText << endl;

     //cout << "Binary representation of output: ";  outputBits(changedText, changedText.size() * 8);

     writeToFile(argv[4], changedText);
}

//===============================================================================

string initialPermutation(string block)
{
     const int initialPermutationTable[4][16] = {{58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4},
                                                 {62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8},
                                                 {57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3},
                                                 {61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7}};

     int bitValue;

     string temp = getZeroString(8); 

     for(int i = 0; i < 4; i++)
     {
          for(int j = 0; j < 16; j++)
          {
               bitValue = getBit(initialPermutationTable[i][j], block); 
                    // get the bit at that position in the table

               putBit(i * 16 + j + 1, bitValue, temp);
          }
     }

     return temp;

}

//===============================================================================

string keyPermutation(string key)
{
     const int keyPermutationTable[4][14] = {{57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18},
                                             {10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36},
                                             {63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22},
                                             {14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4}};

     string temp = getZeroString(7); // they key will be 56 bits after
                                     // omitting the 8th bit, so 7 chars

     int bitValue;

     for(int i = 0; i < 4; i++)
     {
          for(int j = 0; j < 14; j++)
          {
               bitValue = getBit(keyPermutationTable[i][j], key); 
                    // get the bit at that position in the table

               putBit(i * 14 + j + 1, bitValue, temp);
          }
     }

     return temp;
}

//===============================================================================

string shiftKey(string key, int roundNumber, int mode)
{
     const int keyShiftsPerRound[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

     string temp = getZeroString(7); // get a new 56-bit string to use

     int bit1, bit2, putPosition1, putPosition2; // one for each half

     if(mode == 0)
     {
          for(int i = 1; i <= 28; i++)
          {
               bit1 = getBit(i, key); // get bit for left half
               bit2 = getBit(i + 28, key); // get bits for other half

               putPosition1 = i - keyShiftsPerRound[roundNumber];      // find position for left and right halves
               putPosition2 = i + 28 - keyShiftsPerRound[roundNumber];

               if(putPosition1 < 1)
                    putPosition1 += 28; // if they go past the left bound

               if(putPosition2 < 29)
                    putPosition2 += 28;

               putBit(putPosition1, bit1, temp); // put bits in shifted place in new string
               putBit(putPosition2, bit2, temp);
          }
     }
     else
     {
          for(int i = 1; i <= 28; i++)
          {
               bit1 = getBit(i, key); // get bit for left half
               bit2 = getBit(i + 28, key); // get bits for other half

               putPosition1 = i + keyShiftsPerRound[roundNumber];      // find right-shifted position for left and right halves
               putPosition2 = i + 28 + keyShiftsPerRound[roundNumber];

               if(putPosition1 > 28)
                    putPosition1 -= 28; // if they go past the left bound

               if(putPosition2 > 56)
                    putPosition2 -= 28;

               putBit(putPosition1, bit1, temp); // put bits in shifted place in new string
               putBit(putPosition2, bit2, temp);
          }
     }

     return temp;
}

//===============================================================================

string compressionPermutation(string key)
{
     const int compressionPermutationTable[4][12] = {{14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10},
                                                     {23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2},
                                                     {41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48},
                                                     {44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32}};

     string temp = getZeroString(6); // compressing to 48-bit key


     int bitValue;

     for(int i = 0; i < 4; i++)
     {
          for(int j = 0; j < 12; j++)
          {
               bitValue = getBit(compressionPermutationTable[i][j], key); 
                    // get the bit at that position in the table

               putBit(i * 12 + j + 1, bitValue, temp);
          }
     }

     return temp;

}

//===============================================================================

string expansionPermutation(string data)
{
     const int expansionPermutationTable[4][12] = {{32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9},
                                                   { 8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17},
                                                   {16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25},
                                                   {24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1}};

     string temp = getZeroString(6); // expanding to 48-bit data

     int bitValue;

     for(int i = 0; i < 4; i++)
     {
          for(int j = 0; j < 12; j++)
          {
               bitValue = getBit(expansionPermutationTable[i][j] + 32, data); // add 32 because its the
                                                                              // RIGHT half of the data 
                    // get the bit at that position in the table

               putBit(i * 12 + j + 1, bitValue, temp);
          }
     }

     return temp;
}

//===============================================================================

string xorTheKeyAndData(string key, string data)
{
     string temp = getZeroString(6); // result will be 48-bits, XOR'ing the
                                     // compressed key and the expanded right
                                     // half of the permuted data.

     for(int i = 0; i < 6; i++)
          temp.at(i) = key.at(i) ^ data.at(i); // '^' is the operator for XOR (bitwise)

     return temp;
}

//===============================================================================

string sBoxPermutation(string data, const int sBoxTables[8][4][16])
{
     string temp = getZeroString(4); // shrinking down to 32-bit data from 48

     int bitValue, bit1, bit2, bit3, bit4, bit5, bit6, row, col;
     int bitIndex = 1;
     int tableNo = 0;

     for(int i = 0; i < 4; i++)
     {
          bit1 = bitIndex;
          bit2 = bitIndex + 1;
          bit3 = bitIndex + 2;
          bit4 = bitIndex + 3;
          bit5 = bitIndex + 4;
          bit6 = bitIndex + 5;

          row = getRowIndex(getBit(bit1, data), getBit(bit6, data));
               // get the bit at position 1 and 6, then use those numbers
               // to determine which column to use

          col = getColIndex(getBit(bit2, data), getBit(bit3, data),
                            getBit(bit4, data), getBit(bit5, data));

          temp.at(i) = temp.at(i) | (sBoxTables[tableNo][row][col] * 16); // this will OR with the LEFT half of the byte
                                                                    // since the table returns 4 bit integers. 
                                                                    // For instance, to OR the left with 9...
                                                                    //      9 = 00001001 that's no good bc its on the right
                                                                    //      9 * 16 = 72
                                                                    //    144 = 10010000 NOW if we OR that with 0
                                                                    //  OR  0   00000000
                                                                    //        = 10010000 That's better  
         
          bitIndex += 6;
          tableNo++;

          bit1 = bitIndex;
          bit2 = bitIndex + 1;
          bit3 = bitIndex + 2;
          bit4 = bitIndex + 3;
          bit5 = bitIndex + 4;
          bit6 = bitIndex + 5;

          row = getRowIndex(getBit(bit1, data), getBit(bit6, data));
               // get the bit at position 1 and 6, then use those numbers
               // to determine which column to use

          col = getColIndex(getBit(bit2, data), getBit(bit3, data),
                            getBit(bit4, data), getBit(bit5, data));

          temp.at(i) = temp.at(i) | (sBoxTables[tableNo][row][col]);     // Now, using the result from the previous comment and
                                                                         // the next S-box table, we can OR with the right side.
                                                                         // Say the s-box table returns 15
                                                                         //    144 = 10010000
                                                                         // OR  15 = 00001111
                                                                         //        = 10011111 Hooray!
         
          bitIndex += 6;
          tableNo++;
     }

     return temp;
}

//===============================================================================

string pBoxPermutation(string data)
{
     const int straightPermutationTable[2][16] = {{16, 7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10},
                                                  { 2, 8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25}};

     string temp = getZeroString(4); // compressing to 48-bit key


     int bitValue;

     for(int i = 0; i < 2; i++)
     {
          for(int j = 0; j < 16; j++)
          {
               bitValue = getBit(straightPermutationTable[i][j], data); 
                    // get the bit at that position in the table

               putBit(i * 16 + j + 1, bitValue, temp);
          }
     }

     return temp;

     
}

//===============================================================================

string xorLeftHalf(string data, string pboxResults)
{
    string temp = getZeroString(4); // get a 64-bit temp variable
    
    temp = data.substr(0,4); // get the left half of the data
    
    for(int i = 0; i < 4; i++)
        data.at(i) = temp.at(i) ^ pboxResults.at(i); // XOR the pboxResults with the left half
                                                     // and put it into the data
                                                     
    return data;
}

//===============================================================================

string switchHalves(string data)
{
    string temp = getZeroString(4);
    
    for(int i = 0; i < 4; i++)
    {
        temp.at(i) = data.at(i + 4);
        data.at(i + 4) = data.at(i);
        data.at(i) = temp.at(i);
    }
    
    return data;
}

//===============================================================================

string finalPermutation(string data)
{
    const int finalPermutationTable[4][16] = {{40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31},
                                              {38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29},
                                              {36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27},
                                              {34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25}};   
                                              
    int bitValue;

    string temp = getZeroString(8); 

    for(int i = 0; i < 4; i++)
    {
        for(int j = 0; j < 16; j++)
        {
            bitValue = getBit(finalPermutationTable[i][j], data); 
                // get the bit at that position in the table

            putBit(i * 16 + j + 1, bitValue, temp);
          }
     }

     return temp;
}

//===============================================================================

int getRowIndex(int bit1, int bit2) // bit1 = X00000, bit2 = 00000X
{
     char rowIndex = 0; // use a char for 1 byte

     if(bit1 == 1) // we don't need to do anything if its 0 b/c its already 0
          rowIndex = rowIndex | 2; // set that bit 
                                   //    0000 0000
                                   // OR 0000 0010 
                                   //  = 0000 0010
     
     if(bit2 == 1)
          rowIndex = rowIndex | 1; // set that bit 
                                   // (0) 0000 0000  (or possibly) (2) 0000 0010
                                   //  OR 0000 0001                 OR 0000 0001
                                   //   = 0000 0001                  = 0000 0011

     return (int) rowIndex;
}

//===============================================================================

int getColIndex(int bit1, int bit2, int bit3, int bit4) // 0XXXX0 1-4 from L to R
{
     char colIndex = 0; // use a char for 1 byte

     if(bit1 == 1)
          colIndex = colIndex | 8;

     if(bit2 == 1)
          colIndex = colIndex | 4;

     if(bit3 == 1) // we don't need to do anything if its 0 b/c its already 0
          colIndex = colIndex | 2; // set that bit 
     
     if(bit4 == 1)
          colIndex = colIndex | 1; // set that bit 

     return (int) colIndex;
}



//===============================================================================

// this method returns an all zero string with length 8 so that we can modify
// it bitwise without causing problems.

string getZeroString(int length)
{
     string temp = "";

     for(int i = 0; i < length; i++)
     {
          temp += i;
          temp.at(i) = 0;
     }

     return temp;
}

//===============================================================================

int getBit(int bitPosition, string block)
{
     int quotient = bitPosition / 8;
     int remainder = bitPosition % 8;
     int result;

     if(remainder == 0)
     {
          quotient--;
          remainder = 8;
     }

     switch (remainder)
     {
          case 1:
               result = block.at(quotient) & 128;
               break;

          case 2:
               result = block.at(quotient) & 64;
               break;

          case 3:
               result = block.at(quotient) & 32;
               break;

          case 4:
               result = block.at(quotient) & 16;
               break;

          case 5:
               result = block.at(quotient) & 8;
               break;

          case 6:
               result = block.at(quotient) & 4;
               break;

          case 7:
               result = block.at(quotient) & 2;
               break;

          case 8:
               result = block.at(quotient) & 1;
               break;
     }

     if(result > 0)
          return 1;

     else
          return 0;
}

//===============================================================================

void putBit(int bitPosition, int bitValue, string& block)
{

     if(bitValue == 1)// if its not equal to 1, don't do anything! its already 0
     {
          int quotient = bitPosition / 8;
          int remainder = bitPosition % 8;

          if(remainder == 0)
          {
               quotient--;
               remainder = 8;
          }

          switch (remainder)
          {
               case 1:
                    block.at(quotient) = block.at(quotient) | 128;
                    break;

               case 2:
                    block.at(quotient) = block.at(quotient) | 64;
                    break;

               case 3:
                    block.at(quotient) = block.at(quotient) | 32;
                    break;

               case 4:
                    block.at(quotient) = block.at(quotient) | 16;
                    break;

               case 5:
                    block.at(quotient) = block.at(quotient) | 8;
                    break;

               case 6:
                    block.at(quotient) = block.at(quotient) | 4;
                    break;

               case 7:
                    block.at(quotient) = block.at(quotient) | 2;
                    break;

               case 8:
                    block.at(quotient) = block.at(quotient) | 1;
                    break;
          }

     }
}

//===============================================================================

void writeToFile(string outputFileName, string text)
{
     ofstream outputFile;
     outputFile.open(outputFileName.c_str());

     if(!outputFile)
     {
          cout << "Bad file name. Please try again." << endl;
          //system.exit(0); // quit
     }

     outputFile << text; // write to file

     outputFile.close();

     cout << "File write to " << outputFileName << " complete." << endl;

     return;
}

//===============================================================================

string getFileText(string inputFileName)
{
     string input = "";
     char buffer;

     ifstream inputFile;
     inputFile.open(inputFileName.c_str());

     if(!inputFile)
     {
          cout << "Bad file name. Please try again." << endl;
     }

     while(inputFile.get(buffer))
          input = input + buffer;
     
     inputFile.close();

     return input;         
}

//===============================================================================

void outputKey(string block) // outputs the bits of the 1st byte of a string
{
     for(int i = 1; i <= 28; i++)
          cout << getBit(i,block);

     cout << "         ";

     for(int i = 1; i <= 28; i++)
          cout << getBit(i+28,block);

     cout << endl;
}

//===============================================================================

void outputBits(string block, int bitlength) // outputs the bits of the 1st byte of a string
{
     for(int i = 1; i <= bitlength; i++)
          cout << getBit(i,block);

     cout << endl;
}


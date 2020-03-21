//
//  main.m
//  Hex2Bin
//
//  Created by Mikalai Silivonik on 2016-06-29.
//  Copyright © 2016 Mikalai Silivonik. All rights reserved.
//

#include <sys/stat.h>


/**********************************************************************
 *
 * Filename:    main.c
 *
 * Description: Main file
 *
 * Notes:
 *
 *
 *
 * Copyright (c) 2014 Francisco Javier Lana Romero
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define C_FirstCharacter	1
#define C_HeadSize			8
#define C_ChecksumSize		2
#define C_StringEnd			2
#define C_LineSize			(C_FirstCharacter + C_HeadSize + 255 + C_ChecksumSize + C_StringEnd ) * 2
#define C_BinaryFileSize    128

typedef enum
{
    E_SegmentAddress = 0,
    E_LinearAddress
}Enum_MemoryType;

typedef enum
{
    E_OK = 1,
    E_InProcess = 0,
    E_FileNotFound = -1,
    E_CheckSum = -2,
    E_IncompatibleFile = -3,
    E_MemoryAllocation = -4,
    E_EndianesIncompatibleBits = -5
}Enum_Errors;


typedef struct __attribute__((packed)) {
    int16_t crc;
    int8_t major;
    int8_t minor;
    int8_t patch;
    int8_t imageType;
    int8_t startAddress1;
    int8_t startAddress2;
    int8_t startAddress3;
    int8_t length1;
    int8_t length2;
    int8_t length3;
} ImageMetadata;


#define PRINT_OPAQUE_STRUCT(p)  print_mem((p), sizeof(*(p)))

void print_mem(void const *vp, size_t n)
{
    unsigned char const *p = (unsigned char const*)vp;
    size_t i;
    for (i=0; i<n; i++) {
        printf("%02x", p[i]);
    }
};



int8_t F_TransformHexIntelFileToBin(const int8_t S_HexFile[], uint32_t VF_FileSize, const int8_t S_BinFile[], uint8_t VF_FillPathern, uint32_t VF_MemoryInitAddress, uint8_t VF_EndianessBits);


int8_t F_ConvertAsciiToNumeric(int8_t VF_Ascii)
{
    if (VF_Ascii >= '0' && VF_Ascii <= '9')
    {
        return (VF_Ascii - 0x30);
    }
    else if (VF_Ascii >= 'a' && VF_Ascii <= 'f')
    {
        return (VF_Ascii - 87);
    }
    else if (VF_Ascii >= 'A' && VF_Ascii <= 'F')
    {
        return (VF_Ascii - 55);
    }
    return 0xFF;
}

int8_t F_ConvertArrayFromAsciiToNumeric(int8_t A_Data[], int VF_DataSize, int8_t A_ConvertedData[])
{
    int VF_ArrayPos = 0;
    int VF_Result = 0;
    for (VF_ArrayPos = 0; VF_ArrayPos < VF_DataSize; VF_ArrayPos = VF_ArrayPos + 2)
    {
        VF_Result = F_ConvertAsciiToNumeric(A_Data[VF_ArrayPos + 1]) + ((F_ConvertAsciiToNumeric(A_Data[VF_ArrayPos])) << 4);
        if (VF_Result > 0xFF)
        {
            return 0;
        }
        A_ConvertedData[VF_ArrayPos / 2] = VF_Result;
    }
    return 1;
}




uint8_t F_TranformArrayFromLittleEndianToBigEndian(uint8_t VF_EndianessBits, uint8_t VF_ArraySize, uint8_t AF_LittleEndian[], uint8_t AF_BigEndian[])
{
    uint8_t * AF_BigEndianTmp = (uint8_t *) malloc (VF_ArraySize * sizeof (uint8_t));
    uint8_t VF_8bitRegisters = VF_EndianessBits / 8;
    uint8_t VF_ArrayPos = 0;
    uint8_t VF_RegisterPos = 0;
    uint8_t VF_RegisterBytePos = 0;
    if ( VF_ArraySize % VF_8bitRegisters != 0)
    {
        return E_IncompatibleFile;
    }
    while (VF_ArrayPos < VF_ArraySize)
    {
        for ( VF_RegisterBytePos = 1; VF_RegisterBytePos <= VF_8bitRegisters;  VF_RegisterBytePos++)
        {
            AF_BigEndianTmp[VF_ArrayPos++] = AF_LittleEndian[VF_RegisterPos + VF_8bitRegisters - VF_RegisterBytePos];
        }
        VF_RegisterPos = VF_RegisterPos + VF_8bitRegisters;
    }
    for (VF_ArrayPos = 0; VF_ArrayPos < VF_ArraySize; VF_ArrayPos++)
    {
        AF_BigEndian[VF_ArrayPos] = AF_BigEndianTmp[VF_ArrayPos];
    }
    free(AF_BigEndianTmp);

    return E_OK;
}




int8_t F_TransformHexIntelFileToBin(const int8_t S_HexFile[], uint32_t VF_FileSize, const int8_t S_BinFile[], uint8_t VF_FillPathern, uint32_t VF_MemoryInitAddress, uint8_t VF_EndianessBits)
{
    int8_t ** A_BinaryData = 0;
    int8_t ** A_BinaryDataTmp = 0;
    uint32_t* A_DetectedMemoryBanks = 0;
    uint32_t* A_DetectedMemoryBanksTmp = 0;
    int8_t* AF_FileAsciiRow = 0;
    int8_t * AF_FileRowInHex = 0;
    FILE *F_HexadecimalFile = 0;            /* declare the file pointer */
    FILE *F_BinaryFile = 0;


    uint8_t VP_Num_Bytes = 0;
    uint16_t VP_16bitsAddress = 0;
    uint8_t VF_Type = 0;
    uint8_t VF_Checksum = 0;
    uint32_t VF_PhysicalAddress = 0;
    uint16_t VF_High_Address = 0;
    uint16_t VF_AF_FileRowInHexPos = 0;
    uint16_t VF_SegmentedMemoryAddress = 0;
    uint16_t VF_S_BinFilePos = 0;


    uint32_t VF_A_BinaryDataPos = 0;

    Enum_MemoryType E_MemoryType;
    Enum_Errors E_OperationResult = E_InProcess;

    uint16_t VP_MemoryBanksCounter = 0;
    uint16_t VP_CurrentBank = 0;





    F_HexadecimalFile = fopen ((const char *)S_HexFile, "rt");  /* open the file for reading */
    if ( F_HexadecimalFile == NULL)
    {

        return E_FileNotFound;
    }

    if ( VF_EndianessBits % 8 != 0)
    {
        return E_EndianesIncompatibleBits;
    }

    A_DetectedMemoryBanks = (uint32_t*) malloc( 1 * sizeof (uint32_t));
    AF_FileAsciiRow = (int8_t *) malloc (C_LineSize * sizeof (int8_t));

    while(fgets((char*)AF_FileAsciiRow, C_LineSize, F_HexadecimalFile) != NULL && E_OperationResult == E_InProcess)
    {
        int16_t VP_TamanoArrayHex = 0;
        if (AF_FileAsciiRow[0] != ':')
        {
            E_OperationResult = E_IncompatibleFile;
            break;
        }
        for ( VP_TamanoArrayHex = 1; VP_TamanoArrayHex < C_LineSize && AF_FileAsciiRow[VP_TamanoArrayHex] != 0 ; VP_TamanoArrayHex++)
        {
            if ( AF_FileAsciiRow[VP_TamanoArrayHex] == '\r' || AF_FileAsciiRow[VP_TamanoArrayHex] == '\n')
            {
                VP_TamanoArrayHex--;
                break;
            }
            if (((AF_FileAsciiRow[VP_TamanoArrayHex] >= '0' && AF_FileAsciiRow[VP_TamanoArrayHex] <= '9') ||
                 (AF_FileAsciiRow[VP_TamanoArrayHex] >= 'a' && AF_FileAsciiRow[VP_TamanoArrayHex] <= 'f') ||
                 (AF_FileAsciiRow[VP_TamanoArrayHex] >= 'A' && AF_FileAsciiRow[VP_TamanoArrayHex] <= 'F') ) == 0)
            {
                VP_TamanoArrayHex = C_LineSize;
            }
        }
        if ( VP_TamanoArrayHex == C_LineSize )
        {
            E_OperationResult = E_IncompatibleFile;
            break;
        }
        AF_FileRowInHex = (int8_t*) malloc ( ((VP_TamanoArrayHex)/2)* sizeof(int8_t));
        if ( AF_FileRowInHex == NULL)
        {

            E_OperationResult =  E_MemoryAllocation;
            break;
        }

        if ( F_ConvertArrayFromAsciiToNumeric(&AF_FileAsciiRow[1], VP_TamanoArrayHex, AF_FileRowInHex) == 0 )
        {

            E_OperationResult = E_IncompatibleFile;
            break;
        }
        VF_Checksum = AF_FileRowInHex[(VP_TamanoArrayHex - C_ChecksumSize)/2];
        VP_Num_Bytes = AF_FileRowInHex[0];
        VP_16bitsAddress = ((((uint16_t) AF_FileRowInHex[1]) << 8) & 0xFF00) + (((uint16_t) AF_FileRowInHex[2]) & 0xFF);
        VF_Type = AF_FileRowInHex[3];
        VF_AF_FileRowInHexPos = 4;

        VF_Checksum = VF_Checksum +  AF_FileRowInHex[0] +  AF_FileRowInHex[1] +  AF_FileRowInHex[2] + AF_FileRowInHex[3] ;


        switch (VF_Type)
        {
                //Registro de Datos
            case 0:

                if ( VF_EndianessBits > 0)
                {
                    uint8_t VF_Resultado =  F_TranformArrayFromLittleEndianToBigEndian(VF_EndianessBits, VP_Num_Bytes, (uint8_t*)&AF_FileRowInHex[4], (uint8_t*)&AF_FileRowInHex[4]);
                    if ( VF_Resultado  != E_OK)
                    {
                        return VF_Resultado;
                    }

                }
                if (E_MemoryType == E_SegmentAddress)
                {
                    VF_PhysicalAddress = ((((uint32_t) VF_SegmentedMemoryAddress) << 4) & 0xFFFF0) + (((uint32_t) VP_16bitsAddress) & 0xFFFF);
                }
                else
                {
                    VF_PhysicalAddress = ((((uint32_t) VF_High_Address) << 16) & 0xFFFF0000) + (((uint32_t) VP_16bitsAddress) & 0xFFFF);
                }



                for (VP_CurrentBank = 0; VP_CurrentBank < VP_MemoryBanksCounter; VP_CurrentBank++)
                {
                    if (A_DetectedMemoryBanks[VP_CurrentBank] == (int)(VF_PhysicalAddress / VF_FileSize))
                    {
                        break;
                    }
                }
                if (VP_CurrentBank == VP_MemoryBanksCounter)
                {
                    A_DetectedMemoryBanksTmp =  (uint32_t*) realloc ( A_DetectedMemoryBanks, (VP_MemoryBanksCounter + 1) * sizeof (uint32_t));

                    if ( A_DetectedMemoryBanksTmp == NULL )
                    {
                        E_OperationResult =  E_MemoryAllocation;
                        break;
                    }
                    else
                    {
                        A_DetectedMemoryBanks = A_DetectedMemoryBanksTmp;
                    }

                    A_DetectedMemoryBanks[VP_MemoryBanksCounter] = (VF_PhysicalAddress / VF_FileSize);

                    if ( A_BinaryData == NULL)
                    {
                        A_BinaryData = (int8_t**) malloc ( 1 * sizeof (int8_t*));
                    }
                    else
                    {
                        A_BinaryDataTmp = (int8_t**) realloc (A_BinaryData, (VP_MemoryBanksCounter + 1) * sizeof (int8_t*));
                        if ( A_BinaryDataTmp == NULL )
                        {
                            E_OperationResult = E_MemoryAllocation;
                            break;
                        }
                        else
                        {
                            A_BinaryData = A_BinaryDataTmp;
                        }
                    }
                    if ( A_BinaryData == NULL)
                    {
                        E_OperationResult = E_MemoryAllocation;
                        break;
                    }

                    A_BinaryData[(VP_MemoryBanksCounter)] = (int8_t*) malloc ( VF_FileSize * sizeof (int8_t));

                    if ( A_BinaryData[(VP_MemoryBanksCounter)] == NULL)
                    {
                        E_OperationResult = E_MemoryAllocation;
                        break;
                    }

                    //Rellenamos el array con FF por las memor�as Flash
                    for (VF_A_BinaryDataPos = 0; VF_A_BinaryDataPos < VF_FileSize; VF_A_BinaryDataPos++)
                    {
                        A_BinaryData[VP_MemoryBanksCounter][VF_A_BinaryDataPos] = VF_FillPathern;
                    }
                    VP_MemoryBanksCounter++;

                }


                VF_PhysicalAddress = VF_PhysicalAddress % VF_FileSize;


                for (VF_A_BinaryDataPos = 0; VF_A_BinaryDataPos < VP_Num_Bytes; VF_A_BinaryDataPos++)
                {
                    A_BinaryData[VP_CurrentBank][VF_PhysicalAddress++] = AF_FileRowInHex[VF_AF_FileRowInHexPos];
                    VF_Checksum = (VF_Checksum + AF_FileRowInHex[VF_AF_FileRowInHexPos++]);
                }

                if (VF_Checksum != 0)
                {

                    E_OperationResult = E_CheckSum;
                    break;
                }

                break;

                //Fin de fichero
            case 1:
                if ( VF_Checksum != 0)
                {
                    E_OperationResult = E_CheckSum;
                    break;
                }
                while(fgets((char*)AF_FileAsciiRow, C_LineSize, F_HexadecimalFile) != NULL)
                {
                }
                E_OperationResult = E_OK;
                break;

                //Zona de memoria de segmento extendido, permite hasta 1Mb de memoria
            case 2:
                E_MemoryType = E_SegmentAddress;
                VF_SegmentedMemoryAddress = ((((uint16_t) AF_FileRowInHex[VF_AF_FileRowInHexPos]) << 8) & 0xFF00) + (((uint16_t) AF_FileRowInHex[VF_AF_FileRowInHexPos + 1]) & 0xFF);
                VF_Checksum = (AF_FileRowInHex[VF_AF_FileRowInHexPos + 1] + AF_FileRowInHex[VF_AF_FileRowInHexPos] + VF_Checksum);
                if (VF_Checksum != 0)
                {
                    E_OperationResult = E_CheckSum;
                    break;
                }
                break;

            case 3:
                break;
                //Zona de memoria lineal extendida, permite hasta 4GiB
            case 4:
                E_MemoryType = E_LinearAddress;
                VF_High_Address = ((((uint16_t) AF_FileRowInHex[VF_AF_FileRowInHexPos]) << 8) & 0xFF00) + (((uint16_t) AF_FileRowInHex[VF_AF_FileRowInHexPos + 1]) & 0xFF);

                VF_Checksum = (AF_FileRowInHex[VF_AF_FileRowInHexPos + 1] + AF_FileRowInHex[VF_AF_FileRowInHexPos] + VF_Checksum);

                if (VF_Checksum != 0)
                {
                    E_OperationResult = E_CheckSum;
                    break;
                }
                break;
            case 5:
                break;
            default:
                break;
        }
        free(AF_FileRowInHex);
    }

    fclose(F_HexadecimalFile);
    free(AF_FileAsciiRow);
    if ( E_OperationResult != E_OK)
    {
        for (VP_CurrentBank = 0; VP_CurrentBank < VP_MemoryBanksCounter; VP_CurrentBank++)
        {
            free(A_BinaryData[VP_CurrentBank]);
        }
        free(A_BinaryData);
        free(A_DetectedMemoryBanks);
        return E_OperationResult;
    }


    VF_S_BinFilePos = strlen((const char*)S_BinFile);
    while ( VF_S_BinFilePos > 0 )
    {
        if (S_BinFile[VF_S_BinFilePos] == '.')
        {
            break;
        }
        VF_S_BinFilePos--;
    }

    for (VP_CurrentBank = 0; VP_CurrentBank < VP_MemoryBanksCounter; VP_CurrentBank++)
    {
        if ( VF_MemoryInitAddress / VF_FileSize == A_DetectedMemoryBanks[VP_CurrentBank])
        {
            sprintf((char*)&S_BinFile[VF_S_BinFilePos], "%s", ".bin");
        }
        else
        {
            sprintf((char*)&S_BinFile[VF_S_BinFilePos], " 0x%X%s", A_DetectedMemoryBanks[VP_CurrentBank]* VF_FileSize, ".bin");
        }
        F_BinaryFile = fopen ((const char *)S_BinFile, "wb");
        fwrite (A_BinaryData[VP_CurrentBank] , sizeof(int8_t), VF_FileSize, F_BinaryFile);
        fclose (F_BinaryFile);
    }

    for (VP_CurrentBank = 0; VP_CurrentBank < VP_MemoryBanksCounter; VP_CurrentBank++)
    {
        free(A_BinaryData[VP_CurrentBank]);
    }
    free(A_BinaryData);
    free(A_DetectedMemoryBanks);

    //return "OK";
    return E_OperationResult;

}



uint16_t crc16(uint16_t crc, uint8_t val)
{
    const uint16_t poly = 0x1021;
    uint8_t cnt;

    for(cnt = 0; cnt < 8; cnt++, val <<= 1)
    {
        uint8_t msb = (crc & 0x8000) ? 1 : 0;

        crc <<= 1;

        if(val & 0x80)
        {
            crc |= 0x0001;
        }

        if(msb)
        {
            crc ^= poly;
        }
    }

    return(crc);
}


ImageMetadata calcmeta(const char *S_BinFile) {
    long int startAddress = 0x1000;

    // open binary file
    FILE *fp = fopen(S_BinFile, "rb");
    //FILE *fp = fopen("/Users/mikalai/Downloads/CC2640_AppStack-1.hex.bin", "rb");

    // obtain file size:
    fseek (fp , 0 , SEEK_END);
    long int binFileSize = ftell (fp);
    rewind (fp);

    // read binary file into buffer
    int8_t *bin = (int8_t*)malloc(sizeof(int8_t) * binFileSize);
    if (fread (bin, 1, binFileSize, fp) != binFileSize)
    {
        fputs ("Error reading binary file\r\n", stderr);
        exit (3);
    }

    long int i;

    // calculate end address
    long int endAddress = binFileSize - 1;
    for(i = endAddress; i >= startAddress; i--)
    {
        if (bin[i] != (char)0xFF)
        {
            endAddress = i;
            break;
        }
    }

    // round up end address so result length is multiple of 4
    endAddress |= 0x3;

    // calculate crc
    uint16_t crc = 0;
    for (i = startAddress; i <= endAddress; i ++) {
        crc = crc16(crc, bin[i]);
    }
    crc = crc16(crc, 0);
    crc = crc16(crc, 0);

    // create metadata structure
    long int length = (endAddress - startAddress + 1);
    ImageMetadata metadata = {0};
    metadata.crc = crc;
    metadata.major = 0x00;
    metadata.minor = 0x00;
    metadata.patch = 0x00;
    metadata.imageType = 0x01;
    metadata.startAddress1 = startAddress & 0xFF;
    metadata.startAddress2 = startAddress >> 8 & 0xFF;
    metadata.startAddress3 = startAddress >> 16 & 0xFF;
    metadata.length1 = length & 0xFF;
    metadata.length2 = length >> 8 & 0xFF;
    metadata.length3 = length >> 16 & 0xFF;

    free(bin);
    fclose(fp);

    return metadata;
}



int main(int argc, const char * argv[]) {
    uint8_t VF_ArrayPos = 0;
    int8_t *S_HexFile = 0;
    int8_t *S_BinFile = 0;
    int8_t VP_argbPos = 0;
    uint32_t VP_MemoryInitAddress = 0;
    uint32_t VP_MemorySize = C_BinaryFileSize*1024;
    uint8_t VP_FillPathern = 0xFF;
    uint8_t VP_EndianessBits = 0;

    if ( argc <= 1 )
    {

        fprintf (stderr,
                 "\n"
                 "Version: 1.0.1 \n"
                 "Usage: hex2bin.exe filename.hex filename.bin [OPTIONS] \n"
                 "Example: hex2bin.exe myhex.hex mybin.bin /A:1FF /F:FF /S:256 \n"
                 "Options:\n"
                 "  /S [Size]  Size in kB of the .bin file, decimal value. Default value: 256\n"
                 "  /F [Fill]  Fill pattern. Default value FF\n"
                 "  /A [start Address] Starting Address of the memory, hexadecimal value. Default value 0\n"
                 "  /L [Little Endian] If the data in the hex file is written in little endian you should include this parameter "
                 "with the number of bits of each register. For example /L:16 (little endian with 16bit register). "
                 "default parameter is big endian, in big endian the size of the register is not necessary. \n\n"
                 "Return values: \n"
                 "OK = 1 \n"
                 "End of file record not found in .hex file = 0 \n"
                 "File not found = -1 \n"
                 "Checksum Error = -2 \n"
                 "Incompatible File = -3 \n"
                 "Memory Allocation = -4 \n"
                 "Endianness Bits must be 8 multiple = -5 \n"
                 );



        return 0;
    }
    //getchar();
    if ( argc <= 2 ){
        fprintf (stderr,
                 "\n"
                 "too less arguments\n"
        );
        return 0;
    }
    S_HexFile = (int8_t *) malloc ((strlen(argv[0]) + strlen(argv[1])) * sizeof (int8_t));
    S_BinFile = (int8_t *) malloc ((strlen(argv[0]) + strlen(argv[2]) + 20) * sizeof (int8_t));
    strcpy((char*)S_HexFile, argv[0]);
    strcpy((char*)S_BinFile, argv[0]);

    VF_ArrayPos = strlen((const char*)S_HexFile);
    while ( VF_ArrayPos > 0 )
    {
        if (S_HexFile[VF_ArrayPos] == '\\')
        {
            break;
        }
        VF_ArrayPos--;
    }
    if ( VF_ArrayPos != 0)
    {
        VF_ArrayPos++;
    }

    strcpy((char*)&S_HexFile[VF_ArrayPos], argv[1]);
    strcpy((char*)&S_BinFile[VF_ArrayPos], argv[2]);

    for (VP_argbPos = 3; VP_argbPos < argc; VP_argbPos++)
    {
        if (argv[VP_argbPos][1] == 'A' && argv[VP_argbPos][2] == ':')
        {
            for ( VF_ArrayPos = 0; VF_ArrayPos <  strlen(&argv[VP_argbPos][3]); VF_ArrayPos++)
            {
                VP_MemoryInitAddress = (VP_MemoryInitAddress << 4) + F_ConvertAsciiToNumeric(argv[VP_argbPos][VF_ArrayPos + 3]);
            }
        }
        if (argv[VP_argbPos][1] == 'S' && argv[VP_argbPos][2] == ':')
        {
            VP_MemorySize = atoi(&argv[VP_argbPos][3]) * 1024;
        }

        if (argv[VP_argbPos][1] == 'F' && argv[VP_argbPos][2] == ':')
        {
            VP_FillPathern  = 0;
            for ( VF_ArrayPos = 0; VF_ArrayPos < 2; VF_ArrayPos++)
            {
                VP_FillPathern = (VP_FillPathern << 4) + F_ConvertAsciiToNumeric(argv[VP_argbPos][VF_ArrayPos + 3]);
            }
        }

        if (argv[VP_argbPos][1] == 'L' && argv[VP_argbPos][2] == ':')
        {
            VP_EndianessBits = atoi(&argv[VP_argbPos][3]);
        }
    }

    int8_t result = F_TransformHexIntelFileToBin(S_HexFile, VP_MemorySize, S_BinFile, VP_FillPathern, VP_MemoryInitAddress, VP_EndianessBits);




    if (result != E_OK) {
        printf("Result: %d\r\n", result);
        free(S_HexFile);
        free(S_BinFile);
        return 1;
    }

    //printf("Generated binary image\r\n");

    // calculate metadata
    ImageMetadata metadata = calcmeta((const char *)S_BinFile);
    PRINT_OPAQUE_STRUCT(&metadata);
    printf("\r\n");
   //printf("Image metadata: %02x %02x%02x%02x %02x %02x%02x%02x %02x%02x%02x\r\n", metadata.crc, metadata.major, metadata.minor, metadata.patch, metadata.imageType, metadata.startAddress1, metadata.startAddress2, metadata.startAddress3, metadata.length1, metadata.length2, metadata.length3);
    free(S_HexFile);
    free(S_BinFile);
    return 0;
}


/****************************************************************************
* 					Заголовочный файл модуля криптофункций 					*
****************************************************************************/
#ifndef __CRYPTO_H
#define __CRYPTO_H

#ifdef __cplusplus
 extern "C"
 {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/****************************************************************************
* 								Работа с CRC								*
****************************************************************************/

uint8_t CalcCRC8_91(uint8_t *data, uint32_t count, uint8_t InitValue);				// Расчет CRC8

uint8_t CalcCRC8_31_slow(uint8_t *data, uint32_t count, uint8_t InitValue);
uint8_t CalcCRC8_31(uint8_t *lpBlock, uint8_t len);
//uint8_t CalcCRC8_31(uint8_t crc, uint8_t *lpBlock, uint8_t len);

uint8_t CalcCRC8_LLS20xxx(const uint8_t crcInit, const uint8_t * data, const uint8_t len);

uint16_t CalcCRC16(uint8_t *data, uint32_t count, uint16_t InitValue);				// Расчет CRC16


unsigned short Crc16(unsigned char * pcBlock, unsigned short len);

/*
 * Расчет контрольной суммы CRC32 ISO
 * полином  (0xEDB88320) (x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x^1 + 1)
 */
uint32_t crc32_update(uint32_t crc, uint8_t a);


/*
 * Расчет контрольной суммы CRC16 ISO
 * полином  (0xA001)
 */
uint16_t crc16_update(uint16_t crc, uint8_t a);


uint16_t crc16_calc(const uint16_t crcInitValue, const uint8_t *data, const uint16_t dataSize);


size_t CompressRleMatrix(size_t ColumnQuantity, size_t RowQuantity, uint8_t *InBuffer, uint8_t *OutBuffer);


struct RleCompressParameters_t
{
	/*! Количество элементов в строке */
	size_t ColumnNumber;
	/*! Количество строк */
	size_t RowNumber;
	/*! Флаг необходимости транспонирования матрицы перед началом операции сжатия */
	bool TranspositionFlag;
	/*! Флаг частичного сжатия - подсчет длины последовательности производится для каждой строки раздельно */
	bool PartialCompress;
};

size_t CompressRleArray(const void *inputArray, void * outputArray, size_t dataSize);

void Transposition(void * inputData, void * outputData, size_t ColumnNumber, size_t RowNumber);

uint8_t LunhControlSum(uint8_t *Array, size_t ArraySize);

#ifdef __cplusplus
 }
#endif

#endif	// __CRYPTO_H

/****************************************************************************
*								Конец файла									*
****************************************************************************/

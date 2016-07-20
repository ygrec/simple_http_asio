#ifdef WIN32
#define _WIN32_WINNT 0x0501
#include <stdio.h>
#endif
#include <iostream>


#include "crypto.h"
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

#include <boost/date_time.hpp>
#include <time.h>
#include <string>
#include <array>

using namespace boost::asio;
using namespace boost::posix_time;
//using namespace std;
io_service service;

class talk_to_client;
typedef boost::shared_ptr<talk_to_client> client_ptr;
typedef std::vector<client_ptr> array;
array clients;

#define MEM_FN(x)       boost::bind(&self_type::x, shared_from_this())
#define MEM_FN1(x,y)    boost::bind(&self_type::x, shared_from_this(),y)
#define MEM_FN2(x,y,z)  boost::bind(&self_type::x, shared_from_this(),y,z)


void update_clients_changed();

#pragma pack(push, 1)

namespace EGTS
{







/** @defgroup TransportPacketType
  * @{
  */
namespace Transport
{

enum class PacketType	: uint8_t
{
	RESPONSE = 0,
	APPDATA = 1,
	SIGNED_APPDATA = 2,
};

} // namespace Transport

/**
  * @}
  */


enum class Service_t	: uint8_t
{
	/**
	 * ������ ��� ������� ����������� ��� ������������� ��������� �������������� �� (������������ ��) �� ������������ ��.
	 * ��� ������������� TCP/IP ��������� � �������� ����������, �� (������������ ��) ������  ��������� ������  ���������, � ������ ����� ��������� ���������� ������ ��������� ���������� ���������� ��������������.
	 */
	AUTH_SERVICE = 1,

	/**
	 * ������ ������������ ��� ��������� �������������� ���������� (������������ ������, ������ � ������������ �������� � �.�.), ����������� �� ��.
	 * ������ ������ � ��������� ���������
	 */
	TELEDATA_SERVICE = 2,

	/**
	 * ������ ��� ������� ������������ ��� ��������� ����������� � ���������������� ������, �������������� ��������� � ��������, ������������ ����� ��, �� � �����������
	 */
	COMMANDS_SERVICE = 4,

	/**
	 * ������ ������������ ��� �������� �� �� ������������ � ��������������� ������ ������������ ����������� (��) ���������� ����� ������ ��, � ����� ���������� ������������� ������������, ������������� � �� � �������������������������� ��������� ���������� ��
	 */
	FIRMWARE_SERVICE = 9,

	/**
	 * ������, �������������� ���������� ����������� ���.
	 * ������ ������ � ��������� ���������
	 */
	ECALL_SERVICE = 10,
};


/*! ������ ��������� ������������� - ������������� ��� ���� �������� (AUTH_SERVICE, TELEDATA_SERVICE) */
struct SR_RECORD_RESPONSE
{
	//! ����� �������������� ������
	uint16_t ConfirmedRecordNumber;
	//! ������ ��������� ������
	uint8_t RecordStatus;
};

namespace AUTH_SERVICE
{
namespace SubrecordType
{
	enum Enum
	{
		EGTS_SR_RECORD_RESPONSE = 0,	//��������� ����������� ��� ������������� ������������� �������� ��������� ������ ��������� ������ ��������� �����. ������ ��� ��������� ������ �������������� ����� ���������
		EGTS_SR_TERM_IDENTITY = 1,	//��������� ������������ ������ �� ��� ������� ����������� �� ������������ �� � �������� ������� ������ ��
		EGTS_SR_MODULE_DATA = 2,	//��������� ������������� ��� �������� �� �� ���������� �� �������������� �� ������� ��, � �������, ��������� � ���������� ������ � ������� ��. ������ ��������� �������� ������������, � ����������� �� ��� ��������� ������� � ������������� ���������� ����� � �������� ������ ���������. ���� ��������� ��������� ���� ������. � ����� ������ ����� ������������ ��������������� ��������� ����� ����������, ��� ��������� �������� ������ �� ��������� ������������ ���� ���������� ����� �� � ������������� ������������
		EGTS_SR_VEHICLE_DATA = 3,	//��������� ����������� �� ��� �������� �� �� ���������� � ������������ ��������.
		EGTS_SR_DISPATCHER_IDENTITY = 5,	//��������� ������������ ������ ������������ �� ��� ������� ����������� �� ������������ �� � �������� ������� ������ ������������ ��
		EGTS_SR_AUTH_PARAMS = 6,	//��������� ������������ ������������ �� ��� �������� �� �� ������ � ������� � ���������� ����������, ���������� ��� ����������� ��������������
		EGTS_SR_AUTH_INFO = 7, 	//��������� ������������� ��� �������� �� ������������ �� ������������������ ������ �� (������������ ��) � �������������� ����� ���������� �� ������� ������������ �� ���������� ��� ������������� ���������� ������
		EGTS_SR_SERVICE_INFO = 8,	//������ ��� ��������� ������������ ��� �������������� ����������� �������, �� ��� ��, � ����������� �� ����������� ��������, � �������������� ��������, � ����� ��� ������� ������������ ������ ��������� �������� (�� �� � ��)
		EGTS_SR_RESULT_CODE= 9	//��������� ����������� ������������ �� ��� �������������� �� (������������ ��) � ����������� ��������� �������������� ��
	};
} // namespace SubrecordType


typedef struct EGTS::SR_RECORD_RESPONSE SR_RECORD_RESPONSE;

//struct SR_TERM_IDENTITY
//{
//
//};

struct SR_AUTH_PARAM
{
	uint8_t Flags;
	// �������������� ��������� - �� ��������������
	// uint16_t PublicKeyLength;
	// uint8_t PublicKey[0..512];
	// uint16_t IdentityStringLengh;
	// uint16_t ModSize;
	// uint8_t ServerSequence[0..512];
	// uint8_t ServerSequenceDelimeter;
	// uint8_t Exp[0..255];
	// uint8_t ExpDelimeter;
};


struct SR_AUTH_INFO
{
//	uint8_t UserName[32];
//	uint8_t UserNameDelimeter;
//	uint8_t UserPassword[32];
//	uint8_t UserPasswordDelimeter;
//	uint8_t ServerSequence[255];
//	uint8_t ServerSequenceDelimeter;
};

} // namespace AUTH_SERVICE


namespace TELEDATA_SERVICE
{
namespace SubrecordType
{
	enum Enum
	{
		//! ��������� ����������� ��� ������������� ������������� ����� � �������� ����������� ��������� ������ ������ ��������� �����
		RECORD_RESPONSE = 0,

		//! ��������� ������������ �� ��� �������� �������� ������ ����������� ��������������
		POS_DATA = 16,

		//! ��������� ������������ �� ��� �������� �������������� ������ ����������� ��������������
		EXT_POS_DATA = 17,

		//! ���������  ����������� ��  ��� �������� �� �� ���������� � ��������� �������������� ���������� � ���������� ������
		AD_SENSORS_DATA = 18,

		//! ���������  ������������ �� ��� �������� �� �� ������ � �������� ������� ������
		COUNTERS_DATA = 19,

		//! ��������� ������������� ��� �������� �� �� ������ ������� ��������� ��
		ACCEL_DATA = 20,

		//! ������ ��� ��������� ������������ ��� �������� �� �� ���������� � ��������� �� (������� ����� ������, ���������� ��������� � ���������� ���������� ������� � �.�.)
		STATE_DATA = 21,

		//! ��������� ����������� �� ��� �������� �� �� ������ � ��������� ��������� ������ (������������ � �������� ��������)
		LOOPIN_DATA = 22,

		//! ��������� ����������� �� ��� �������� �� �� ������ � ��������� ������ ����������� �����
		ABS_DIG_SENS_DATA = 23,

		//! ���������  �����������  �� ��� �������� �� �� ������ � ��������� ������ ����������� �����
		ABS_AN_SENS_DATA = 24,

		//! ��������� ����������� �� ��� �������� �� �� ������ � ��������� ������ �������� �����
		ABS_CNTR_DATA = 25,

		//! ��������� ����������� �� ��� �������� �� �� ������ � ��������� ������ ���������� �����
		ABS_LOOPIN_DATA = 26,

		//! ��������� ����������� �� ��� �������� �� �� ������ � ���������� ���
		LIQUID_LEVEL_SENSOR = 27,

		//! ��������� ����������� �� ��� �������� �� �� ������ � ���������� ��������� ���������������
		PASSENGERS_COUNTERS = 28,
	};
} // namespace SubrecordType

typedef struct EGTS::SR_RECORD_RESPONSE SR_RECORD_RESPONSE;
} // namespace TELEDATA





struct __attribute__ ((__packed__)) RDStruct
{
	/**
	 * Subrecord Type
	 * ��� ��������� (������ ������������ ������ � ������ ������ ������ ����� ������ �������).
	 * ��� 0 � �����������, �������������� �� ���������� ������������� ������ ��� ������� �������.
	 * ���������� �������� ������� ����� ���������� ������������ ������� ������ �������.
	 * �������� ����������� ���� ��, ��� ���� ����� ������ ��������������, � ������� ������������� ��������������
	 */
	uint8_t SRT;

	/**
	 * Subrecord Length
	 * ����� ������ � ������ ��������� � ���� SRD
	 */
	uint16_t SRL;

	/**
	 * Subrecord Data (0�65495)
	 * ������ ���������.
	 * ���������� ������� ���� ���������� ��� ������� ��������� �������������� ���� ������� � ���� ���������
	 */
	uint8_t SRD[];
};

struct __attribute__ ((__packed__)) TELEDATA_SERVICE_POS_DATAStruct
{
	/*! ����� ��������� ��������� */
	RDStruct Header;
	/**
	 * ����� ��������� (���������� ������ � 00:00:00 01.01.2010 UTC)
	 */
	uint32_t NTM;

	/**
	 * ������ �� ������, ������� / 90 * 0xFFFFFFFF � ����� ����� �����
	 */
	uint32_t LAT;

	/**
	 * ������� �� ������, ������� / 180 * 0xFFFFFFFF � ����� ����� �����
	 */
	uint32_t LONG;

	/**
	* FLG ������� ����� (ALTE, LOHS, LAHS, MV, BB, FIX, CS, VLD)
	* FLG[7] ALTE ������� ���� ALT � ���������: 1 - ���� ALT ����������; 0 - �� ���������
	* FLG[6] LOHS ��������� �������: 0 - ��������� �������; 1 - �������� �������
	* FLG[5] LAHS ��������� ������: 0 - �������� ������; 1 - ����� ������
	* FLG[4] MV ������� ��������: 1 - ��������; 0 - �� ��������� � ������ �������
	* FLG[3] BB ������� �������� ������ �� ������ (������� ����): 0 - ���������� ������; 1 - ������ �� ������ (�������� �����)
	* FLG[2] FIX ��� ����������� ���������: 0 - 2D fix; 1 - 3D fix
	* FLG[1] CS ��� ������������ �������: 0 - WGS-84; 1 - ��-90.02
	* FLG[0] VLD ������� ����������� ������������ ������: 1 - ������ ���������; 0 - ����������� ������
	*/
	uint8_t FLG;

	/**
	* SPD (DIRH, ALTS, SPD[0:13])
	* SPD[15] DIRH (Direction the Highest bit) ������� ��� ��������� DIR
	* SPD[14] ALTS (Altitude Sign) ������� ����, ���������� ������ ������������ ������ ���� � ����� ����� ������ ��� ������������� ����� ALTE
	* SPD[0:13] �������� � ������� ����� ����/� (������������ 14 ������� ���)
	*/
	uint16_t SPD;

	/**
	 * DIR ����������� ��������.
	 * ������������ ��� ���� � ��������, ������� ������������� �� ������� ������� ����� �������� ������������ ��������������� ��������� � ������������ �������� � ����� ��������� (������������� ������� ��� ��������� � ���� DIRH)
	 */
	uint8_t DIR;

	/**
	 * ODM ���������� ���������� (������) � ������� ����� ���������
	 */
	uint8_t ODM[3];

	/**
	 * DIN ������� �����, ���������� ��������� �������� ���������� ������ 1�8 (���� ��� ����� 1, �� ��������������� ���� �������, ���� 0 - ���������).
	 * ������ ���� �������� ��� �������� ������������� � �������� ������� ��� ������ � �������� ����������� ���������� �������� ������
	 */
	uint8_t DIN;

	/**
	 * SRC ���������� �������� (�������), �������������� ������� ������ ������������� ����������
	 */
	uint8_t SRC;
};


struct __attribute__ ((__packed__)) TELEDATA_SERVICE_EXT_POS_DATAStruct
{
	/*! ����� ��������� ��������� */
	RDStruct Header;

	/**
	* Flags ������� ����� (ALTE, LOHS, LAHS, MV, BB, FIX, CS, VLD)
	* Flags[4] NSFE ������� ���� NS: 1 - ���� ����������; 0 - �� ����������
	* Flags[3] SFE ������� ����� SAT � NS: 1 - ���� ����������; 0 - �� ����������
	* Flags[2] PFE ������� ���� PDOP: 1 - ���� ����������; 0 - �� ����������
	* Flags[1] HFE ������� ���� HDOP: 1 - ���� ����������; 0 - �� ����������
	* Flags[0] VFE ������� ���� VDOP: 1 - ���� ����������; 0 - �� ����������
	*/
	uint8_t Flags;

	/**
	 * �������� �������� � ������������ ��������� (��������, ���������� �� 100)
	 */
	uint16_t VDOP;

	/**
	 * �������� �������� � �������������� ��������� (��������, ���������� �� 100)
	 */
	uint16_t HDOP;

	/**
	 * �������� �������� �� �������������� (��������, ���������� �� 100)
	 */
	uint16_t PDOP;

	/**
	* ���������� ������� ���������.
	*/
	uint8_t SAT;

	/**
	* ���������� ������� ���������, ������� �����. 0 - ������� �� ����������
	* Flags[7] QZSS
	* Flags[6] IRNSS
	* Flags[5] Doris
	* Flags[4] Beidou
	* Flags[3] Compass
	* Flags[2] Galileo
	* Flags[1] GPS
	* Flags[0] �������
	*/
	uint16_t NS;
};


struct __attribute__ ((__packed__)) TELEDATA_SERVICE_LOOPIN_DATAStruct
{
	/*! ����� ��������� ��������� */
	RDStruct Header;

	/**
	 * 	LIFE1�LIFE8	� (Loop In Field Exists) ������� �����, ������������ ������� ����������
	 * � ��������� ��������� ������. ��������, ���� ���������� �������� ������ �� �� 1, 3, 8, ����� 1 �����,
	 * ����������� ������� ����� LIFE1=1, LIFE3=1 � LIFE8=1, ����� ������� ���� ����,
	 * ���������� ���������� � ��������� �� 1 � 3, ���� ����, ���������� ���������� � ��������� �� 8 (������� 4 ����);
	 */
	uint8_t LIFE;

	/**
	 * LIS n � LIS n+7	� (Loop In State) �������� ��������� ���������������� ���������� �����.
	 * ������������ ��������.
	 * ������������� ��������� ��������� ���������� ����� (�������� �������������):
	 *	0000 = ������;
	 *	0001 = ��������;
	 *	0010 = ������;
	 *	0100 = ���������� �� ������;
	 *	1000 = ���������� �� �������.
	 */
	uint8_t LIS[4];
};


struct __attribute__ ((__packed__)) TELEDATA_SERVICE_ABS_CNTR_DATA_Struct
{
	/*! ����� ��������� ��������� */
	RDStruct Header;

	/**
	 *	����� �������� �����
	 */
	uint8_t CounterNumber;

	/**
	 *	��������� �������� �����
	 */
	uint8_t CounterValue[3];
};


struct __attribute__ ((__packed__)) TELEDATA_SERVICE_LIQUID_LEVEL_SENSORStruct
{
	/*! ����� ��������� ��������� */
	RDStruct Header;

	/**
	* Flags ������� ����� (ALTE, LOHS, LAHS, MV, BB, FIX, CS, VLD)
	* Flags[6] LLSEF ������� ������ ��� ���������� �������� �������: 1 - ������ ��� ���������� ���������; 0 - ������ �� ����������
	* Flags[5:4] LLSVU ������� ��������� ��������� ���
	* 			00 - �������������� ��������� �������
	* 			01 - ��������� � % �� ������ ������
	* 			10 - ��������� � ������������� 0,1 �
	* Flags[3] RDF - ���� �� ������������ ������� ������.
	* 		0 - ��������� �������� 4 �����, 1 - ��������� �������� 4..512
	* 		���������� ������ 0
	* Flags[2:0] LLSN ���������� ����� �������
	*/
	uint8_t Flags;

	/**
	 *	����� ������, ������ � ���������� ��� � �������� ��������� � �� (����� �������� ����� ��)
	 */
	uint16_t MADDR;

	/**
	 *	��������� ���
	 */
	uint32_t LLSD;
};


struct __attribute__ ((__packed__)) AUTH_SERVICE_TERM_IDENTITYStruct
{
	/*! ����� ��������� ��������� */
	RDStruct Header;

	/**
	 * (Terminal Identifier), ���������� �������������, ����������� ��� ���������������� ��.
	 * ������� �������� 0 � ������ ���� ��������, ��� �� �� ������ ��������� ����������������,
	 * ��� ������ � �� ���������. ������ ������������� ����������� ���������� � ����������
	 * ���������� ����� ������� ������ ��. TID ����������� ��� ����������� �� ��� ���������������
	 * ������������ � �������� ��������� ������� ������ �� (IMSI, IMEI, serial_id).
	 * � ������ ������������� �� � �������� �������� ����������, TID ���������� ���������
	 * ������������������ ������ � �������� ������� (VIN, IMSI, IMEI);
	 */
	uint32_t TID;

	/**
	* FLG ������� ����� (MNE, BSE, NIDE, SSRA, LNGCE, IMSIE, IMEIE, HDIDE)
	* FLG[7] MNE � (Mobile Network Exists), ������� ����, ������������ ������� ���� MSISDN � ��������� (���� ��� ����� 1, �� ���� ���������, ���� 0, �� �� ���������);
	* FLG[6] BSE � (Buffer Size Exists), ������� ����, ������������ ������� ���� BS � ��������� (���� ��� ����� 1, �� ���� ���������, ���� 0, �� �� ���������);
	* FLG[5] NIDE - (Network Identifier Exists), ������� ���� ���������� ������� ���� NID � ��������� (���� ��� ����� 1, �� ���� ���������, ���� 0, �� �� ���������);
	* FLG[4] SSRA � ������� ���� ������������ ��� ����������� ��������� ������������� �������� (���� ��� ����� 1, �� ������������ �������� ��������, ���� 0, �� �������� ��������� �� ������������� C�������);
	* FLG[3] LNGCE � (Language Code Exists), ������� ����, ������� ���������� ������� ���� LNGC � ��������� (���� ��� ����� 1, �� ���� ���������, ���� 0, �� �� ���������);
	* FLG[2] IMSIE � (International Mobile Subscriber Identity Exists), ������� ����, ������� ���������� ������� ���� IMSI � ��������� (���� ��� ����� 1, �� ���� ���������, ���� 0, �� �� ���������);
	* FLG[1] IMEIE � (International Mobile Equipment Identity Exists), ������� ����,  ������� ���������� ������� ���� IMEI � ��������� (���� ��� ����� 1, �� ���� ���������, ���� 0, �� �� ���������);
	* FLG[0] HDIDE � (Home Dispatcher Identifier Exists), ������� ����, ������� ���������� ������� ���� HDID � ��������� (���� ��� ����� 1, �� ���� ���������, ���� 0, �� �� ���������);
	*/
	uint8_t FLG;

	/**
	 * (Home Dispatcher Identifier), ������������� ��������� �� (��������� �������
	 * ���������� � ��������� �������� �� ������ ��);
	 */
	uint16_t HDID;

	/**
	 * (International Mobile Equipment Identity), ������������� ���������� ���������� (������).
	 * ��� ������������� ����������� ������� ���������, �� ������ ��������� ������ ����
	 * ��������� 0 �� ���� 15-�� ��������;
	 */
	char IMEI[15];

	/**
	 * (International Mobile Subscriber Identity), ������������� ���������� ��������.
	 * ��� ������������� ����������� ������� ���������, �� ������ ��������� ������ ����
	 * ��������� 0 �� ���� 16-�� ��������;
	 */
	//char IMSI[16];

	/**
	 * (Language Code), ��� �����, ����������������� � ������������� �� ������� ��, �� ISO 639-2,
	 * ��������, �rus� � �������;
	 */
	//char LNGC[3];

	/**
	 * (Network Identifier), ������������� ���� ���������, � ������� ���������������� �� �� ������ ������.
	 * ������������ 20 ������� ���. ������������ ���� ����� MCC-MNC (�� ������ ������������ ITU-T E.212).
	 */
	//uint8_t NID[3];

	/**
	 * (Buffer Size), ������������ ������ ������ ����� �� � ������. ������ ������� ������ ����������,
	 * ������������� �� ��, �� ������ ��������� ������� ��������. �������� ���� BS ����� ���������
	 * ��������� ��������, �������� 800, 1000, 1024, 2048, 4096 � �.�., � ������� �� ����������
	 * ���������� � ����������� ������ ���������� ��;
	 */
	//uint16_t BS;

	/**
	 * (Mobile Station Integrated Services Digital Network Number), ���������� ����� ���������� ��������.
	 * ��� ������������� ����������� ������� ���������, ���������� ������ ��������� ������ ���� ��������� 0
	 * �� ���� 15-�� ��������
	 */
	//char MSISDN[15];
};


/*! ��������� ������������ ��������� ��������� ������ ��������� ������ ��������� ����� */
struct HeaderSdrMinimal_t
{
	/*! ������ ������ */
	uint16_t RL;
	/*! ����� ������ */
	uint16_t RN;

	/*! ����� �������� ������. [7] SSOD (1), [6] RSOD, [5] GRP, [3:4] RPP, [2] TMFE (1), [1] EVFE, [0] OBFE (1)*/
	uint8_t RFL;

	// ����������� ������ ������������ ������ - 5 ����, �������������� ���� ����������� �����
	// ������������� � ����� ������ ���������� ���� � ���������
	uint8_t data[2];
};


/*! ��������� ��������� ��������� ������ ��������� ������ ��������� ����� */
struct HeaderSDR_t
{
	/*! ������ ������ */
	uint16_t RL;
	/*! ����� ������ */
	uint16_t RN;

	/*! ����� �������� ������ - ������������ 0x85. [7] SSOD (1), [6] RSOD, [5] GRP, [3:4] RPP, [2] TMFE (1), [1] EVFE, [0] OBFE (1)*/
	uint8_t RFL;
	/*! ������������� ������� (������������ 2 ����� �� 4-�) */
	uint32_t OID;
	/*! ����� ������������ ������ */
	uint32_t TM;
	/*! ������������� ���� �������-����������� */
	Service_t SST;
	/*! ������������� ���� �������-���������� */
	Service_t RST;
};


/*! ��������� ��������� ��������� ������ ��������� ����� */
struct SubrecordSSLP
{
	/*! ��������� ��������� */
	RDStruct Header;
	/*! ����� ������ ��������� */
	uint8_t Data[];
};


/*! ��������� ��������� ������ ��������� ������ ��������� ����� */
struct RecordSSLP
{
	/*! ��������� ������ */
	HeaderSDR_t Header;
	/*! ����� ���������� */
	SubrecordSSLP Subrecord[];
};


struct Response_t
{
	/*! ������������� ������ ������������� ������ */
	uint16_t RPID;
	/*! ��� ����������� ��������� ������ */
	uint8_t PR;
};


/*! ��������� ��������� ������ ������������� ������ */
struct HeaderTransport_t
{
	/*! ������ ��������� - ������������ 1 */
	uint8_t PRV;
	/*! ������������� �����, ������������ ��� ���������� - ������������ 0 ��� ���������� ���������� ��� 1 ��� ���� 28147 */
	uint8_t SKID;

	/*! PRF[0:1] (Prefix), RTE, ENA[0:1], CMP, PR[0:1] - ������������ 0 */
	uint8_t Mask_1;

	/*! ����� ��������� ������������� ������ � ������ � ������ ����� ����������� ����� (���� HCS) - 11 ���� */
	uint8_t HL;
	/* ������ */
	uint8_t HE;
	/*! ������ � ������ ���� ������ SFRD, ����������� ���������� ��������� ������ ��������� ����� */
	uint16_t FDL;	// = sizeof(HeaderSDR_t) + SDR_size;
	/*! ����� ������ ������������� ������*/
	uint16_t PID;
	/*! ��� ������ */
	Transport::PacketType PT;
	/*! ����������� ����� ��������� ������������� ������ */
	uint8_t HCS;
};


/*! ��������� ������ ������������� ������ */
struct TransportPacket_t
{
	/*! ��������� ������������� ������ */
	HeaderTransport_t Header;
	/*! ������ ������� */
	RecordSSLP Record[];
};




// ������ ���������
namespace Constants
{
#if defined(__EGTS_STATISTIC__)
	/*! ���������� �������������� ��������� ���������� ���� */
	extern const uint32_t StatisticNumber;
#endif // defined(__EGTS_STATISTIC__)
	enum
	{
		MaxReceivedRecodsInPacket = 10,
	};
}

enum ProcessCode_t
{
	OK = 0, //!< ������� ����������
	IN_PROGRESS = 1, //!< � �������� ��������� (��������� ��������� ��� �� ��������)
	UNS_PROTOCOL = 128, //!< ���������������� ��������
	DECRYPT_ERROR = 129, //!< ������ �������������
	PROC_DENIED = 130, //!< ��������� ���������
	INC_HEADERFORM = 131, //!< �������� ������ ���������
	INC_DATAFORM = 132, //!< �������� ������ ������
	UNS_TYPE = 133, //!< ���������������� ���
	NOTEN_PARAMS = 134, //!< �������� ���������� ����������
	DBL_PROC = 135, //!< ������� ��������� ���������
	PROC_SRC_DENIED = 136, //!< ��������� ������ �� ��������� ���������
	HEADERCRC_ERROR = 137, //!< ������ ����������� ����� ���������
	DATACRC_ERROR = 138, //!< ������ ����������� ����� ������
	INVDATALEN = 139, //!< ������������ ����� ������
	ROUTE_NFOUND = 140, //!< ������� �� ������
	ROUTE_CLOSED = 141, //!< ������� ������
	ROUTE_DENIED = 142, //!< ������������� ���������
	INVADDR = 143, //!< �������� �����
	TTLEXPIRED = 144, //!< ��������� ���������� ������������ ������
	NO_ACK = 145, //!< ��� �������������
	OBJ_NFOUND = 146, //!< ������ �� ������
	EVNT_NFOUND = 147, //!< ������� �� �������
	SRVC_NFOUND = 148, //!< ������ �� ������
	SRVC_DENIED = 149, //!< ������ ��������
	SRVC_UNKN = 150, //!< ����������� ��� �������
	AUTH_DENIED = 151, //!< ����������� ���������
	ALREADY_EXISTS = 152, //!< ������ ��� ����������
	ID_NFOUND = 153, //!< ������������� �� ������
	INC_DATETIME = 154, //!< ������������ ���� � �����
	IO_ERROR = 155, //!< ������ �����/������
	NO_RES_AVAIL = 156, //!< ������������ ��������
	MODULE_FAULT = 157, //!< ���������� ���� ������
	MODULE_PWR_FLT = 158, //!< ���� � ������ ���� ������� ������
	MODULE_PROC_FLT = 159, //!< ���� � ������ ���������������� ������
	MODULE_SW_FLT = 160, //!< ���� � ������ ��������� ������
	MODULE_FW_FLT = 161, //!< ���� � ������ ����������� �� ������
	MODULE_IO_FLT = 162, //!< ���� � ������ ����� �����/������ ������
	MODULE_MEM_FLT = 163, //!< ���� � ������ ���������� ������ ������
	TEST_FAILED = 164, //!< ���� �� �������
};


/*! ��������� ������ ������������� ������ */
struct TransportPacket_t;
/*! ��������� ��������� ������ ������������� ������ */
struct HeaderTransport_t;
/*! ��������� ��������� ������ ��������� ������ ��������� ����� */
struct RecordSSLP;
/*! ��������� ��������� ��������� ������ ��������� ������ ��������� ����� */
struct HeaderSDR_t;
/*! ��������� ��������� ��������� ������ ��������� ����� */
struct SubrecordSSLP;

enum class Service_t : uint8_t;

#if defined(__EGTS_STATISTIC__)
struct Statistic_t
{
	/*! CN = 100, ���������� ���� �������������� �������, ���������� �� ������
	 * �� ������ ������������ ������ EGTS_TELEDATA_SERVICE */
	uint32_t TotalConfirmed;
	/*! CN = 101, ���������� ���� ���������� �������, �.�. ������������ ������, ������� ���� ������� ������ */
	uint32_t Unsent;
	/*! CN = 102, ���������� ���������� � �������� */
	uint32_t ConnectCounter;
};
#endif // defined(__EGTS_STATISTIC__)



/*! ���� �������� ������� ������������ ������/��������� */
enum class FillResultCode
{
	Normal = 0,
	WrongRecord = 1,
	BufferFull = 2,
};

/*! ���� ������ � �������� �� ��������� RTM */
enum class FieldId
{
	/*! ���������� ������ ��������� �����/�������� ���������� ���� */
	StatisticEnable = 0,
	/*! ������ ���������� - ���������� ��������� */
	StatisticContent,
	/*! �������� ��������� */
	StatisticValue,
	/*! ������ �� ��������� ������ ���������� */
	SendCommand,

	/// ���������� ������������� ���������� ��� ������ � ��������
	CryptoEnable,
	/// ���� ���������� �� ���� 28147
	CryptoKey,
	/// ������� ����������� �� ���� 28147
	CryptoTable,
};















namespace Timeout
{
	/*! ����� �������� �������� ������ */
		const uint32_t ChannelClose = 30000;

	/*! ������������ ����� �������� ����������� � ������� (������������ ������ �����) */
#if defined(__SIM_RESERVED__)
	const uint32_t MAX_SERVER_CONNECTION_TIME = 900000;
#else
	const uint32_t MAX_SERVER_CONNECTION_TIME = 300000;
#endif // defined(__SIM_RESERVED__)

	/*! ����� �������� ��� ������� ��������� �������� ������ */
	const uint32_t RETRY_TIMEOUT = 10000;

	/*! ������� �������������� �������� ������ */
	const uint32_t FORCE_SEND_TIMEOUT = 120000;

	/*! ������� �������� ������������� �������� ������ */
	// TODO deprecated - ������ �� TL_RESPONSE_TO
	const uint32_t RESPONSE_TIMEOUT = 30000;

	/*! ������������ ����� ������ ��� ���������� ������ */
	const uint32_t EXCHANGE_INACTIVE_TIMEOUT = 600000;

	/*! ������� �������� ������� �� rtm_binV2 */
	const uint32_t SEND_BIN2_PERIOD = 1000;



	/// ��������� �� ������������ �� �������� ����
	/*! ����� �������� ������������� ������ */
	const uint32_t TL_RESPONSE_TO = 10000;

	/*! ����� �� ����������� */
	const uint32_t EGTS_SL_NOT_AUTH_TO = 600; //6;
} // namespace Timeout

namespace Strings
{

} // namespace Strings

// ������ ���������
namespace Constants
{
	/// ������� ������ ��������� ����
	const uint8_t ProtocolVersion = 1;

	/*! ���������� ������� �������� ������ ����������� */
	const uint8_t AuthenticationRetry = 3;

	/*! ���������� ������� �������� ������ ������ ��� ������ */
	const uint8_t DataSendRetry = 5;

	/*! ���������� ������� �������� ���������� */
	const uint32_t ChannelCloseRetry = 10;

	const clock_t BaseTimeStamp = 1262304000; // POSIX time 0h0m0s, 01.01.2010 UTC

#if defined(__EGTS_STATISTIC__)
	/*! ���������� �������������� ��������� ���������� ���� */
	const uint32_t StatisticNumber = 7;
#endif // defined(__EGTS_STATISTIC__)

	/// ������ ���� SFRCS ������ ������������� ������
	const uint8_t SFRCSLength = 2;


	const char DefaultUserName[] = "Voyager";
	const char DefaultUserPassword[] = "12345678";


	/// ��������� �� ������������ �� �������� ����
	/*! ���������� ������� ��������� �������� ������ ������������� ������ ����� ��������� ������ */
	const uint8_t TL_RESEND_ATTEMPTS = 3;

} // namespace Constants

} // namespace EGTS

#pragma pack(pop)

using namespace EGTS;


void PrintTimeStamp()
{
	boost::date_time::winapi::SYSTEMTIME currentSystemTime;
	boost::date_time::winapi::GetSystemTime(&currentSystemTime);
	std::cout << "Time: " << std::setfill ('0') << currentSystemTime.wHour << ":" << std::setw(2) << currentSystemTime.wMinute << \
			":" << std::setw(2) << currentSystemTime.wSecond << "." << std::setw(3) << currentSystemTime.wMilliseconds << std::endl;
}

/** simple connection to server:
    - logs in just with username (no password)
    - all connections are initiated by the client: client asks, server answers
    - server disconnects any client that hasn't pinged for 5 seconds
    Possible client requests:
    - gets a list of all connected clients
    - ping: the server answers either with "ping ok" or "ping client_list_changed"
*/
class talk_to_client : public boost::enable_shared_from_this<talk_to_client>
                     , boost::noncopyable {
    typedef talk_to_client self_type;
    talk_to_client() : sock_(service), started_(false),
                       timer_(service), clients_changed_(false) {
    }
public:
    typedef boost::system::error_code error_code;
    typedef boost::shared_ptr<talk_to_client> ptr;

    void start() {
//    	std::cout << "srv inst start" << std::endl;
        started_ = true;
        clients.push_back( shared_from_this());
        last_ping = boost::posix_time::microsec_clock::local_time();
        // first, we wait for client to login
        do_read();
    }
    static ptr new_() {
        ptr new_(new talk_to_client);
        return new_;
    }
    void stop() {
        if ( !started_) return;
        started_ = false;
        sock_.close();

        ptr self = shared_from_this();
        array::iterator it = std::find(clients.begin(), clients.end(), self);
        clients.erase(it);
        update_clients_changed();
    }
    bool started() const { return started_; }
    ip::tcp::socket & sock() { return sock_;}
    std::string username() const { return username_; }
    void set_clients_changed() { clients_changed_ = true; }
private:
    void on_read(const error_code & err, size_t bytes) {
    	std::cout << "on_read" << std::endl;
        if ( err) stop();
        if ( !started() ) return;

        // process the msg
        std::string msg(read_buffer_, bytes);
        std::cout << "Rcv msg " << msg << std::endl;

        if ( msg.find("login ") == 0) on_login(msg);
        else if ( msg.find("ping") == 0) on_ping();
        else if ( msg.find("ask_clients") == 0) on_clients();
        else std::cerr << "invalid msg " << msg << std::endl;
    }

    void on_login(const std::string & msg) {
    	std::cout << "on login" << std::endl;
        std::istringstream in(msg);
        in >> username_ >> username_;
        std::cout << username_ << " logged in" << std::endl;
        do_write("login ok\n");
        update_clients_changed();
    }
    void on_ping() {
        do_write(clients_changed_ ? "ping client_list_changed\n" : "ping ok\n");
        clients_changed_ = false;
    }
    void on_clients() {
        std::string msg;
        for( array::const_iterator b = clients.begin(), e = clients.end() ; b != e; ++b)
            msg += (*b)->username() + " ";
        do_write("clients " + msg + "\n");
    }

    void do_ping() {
        do_write("ping\n");
    }
    void do_ask_clients() {
        do_write("ask_clients\n");
    }

    void on_check_ping() {
        boost::posix_time::ptime now = boost::posix_time::microsec_clock::local_time();
        if ( (now - last_ping).total_milliseconds() > 5000) {
            std::cout << "stopping " << username_ << " - no ping in time" << std::endl;
//            stop();
        }
        last_ping = boost::posix_time::microsec_clock::local_time();
    }
    void post_check_ping() {
        timer_.expires_from_now(boost::posix_time::millisec(5000));
        timer_.async_wait( MEM_FN(on_check_ping));
    }


    void on_write(const error_code & err, size_t bytes) {
        do_read();
    }
    void do_read() {
        async_read(sock_, buffer(read_buffer_),
                   MEM_FN2(read_complete,_1,_2), MEM_FN2(on_read,_1,_2));
        post_check_ping();
    }
    void do_write(const std::string & msg) {
        if ( !started() ) return;
        std::copy(msg.begin(), msg.end(), write_buffer_);
        sock_.async_write_some( buffer(write_buffer_, msg.size()),
                                MEM_FN2(on_write,_1,_2));
    }

    bool Parser(uint8_t * Data, size_t DataSize)
    {
    	std::cerr << "Receive packet (total " << DataSize << " bytes): <" << std::endl;

    	for(size_t count = 0; count < DataSize; count++)
    		std::cerr << std::setw(2) << *(Data + DataSize) << " ";
    	std::cerr << ">" << std::endl;


    	uint8_t* buffer = (uint8_t*) Data;
    	uint8_t data_size_loc = (uint8_t)DataSize;
//
//    	if(!Find_start)
//    	{
//    		do
//    		{
//    			//EGTS_PT_RESPONSE packet start byte
//    			if(*buffer == EGTS::Constants::ProtocolVersion)
//    			{
//    				Find_start = 1;
//    				break;
//    			}
//    			buffer++;
//    			data_size_loc--;
//    		}while (data_size_loc);
//    	}
//
//    	if(Find_start)
    	{
    		uint8_t *RxBuffer = Data;
    		// detect EGTS_PT_RESPONSE packet
    		if(DataSize >= sizeof(EGTS::HeaderTransport_t))
    		{
    			uint16_t FrameDataLength = (RxBuffer[6] << 8) + RxBuffer[5];
    //			memcpy(&FrameDataLength, &RxBuffer[5], sizeof(FrameDataLength));
    			if(DataSize >= sizeof(HeaderTransport_t) + FrameDataLength + EGTS::Constants::SFRCSLength)
    			{
    				EGTS::HeaderTransport_t Header;
    				memcpy(&Header, RxBuffer, sizeof(HeaderTransport_t));
    				// HL
    				if(Header.HL == sizeof(HeaderTransport_t))
    				{
    					// PRV
    					if(Header.PRV == EGTS::Constants::ProtocolVersion)
    					{
    						// HCS
    //						if(Header.HCS == CalcCRC8_31(RxBuffer.begin(), Header.HL - 1))
    						uint8_t HCS = CalcCRC8_31(RxBuffer, Header.HL - 1);
    						std::cout.setf (std::ios_base::hex , std::ios_base::basefield);
    						std::cout.setf (std::ios_base::showbase);
    						std::cout << std::setw(4) << std::setfill('.');
    						std::cout << "HCS " << std::setbase(16) <<  HCS << std::endl;
    						{
    							// FDL
    							if(Header.FDL != 0)
    							{
    								// SFRD (��� APP_DATA), RPID (��� APP_RESPONSE)
    								uint8_t *PacketData = RxBuffer + sizeof(Header);
    								// SFRCS
    								uint16_t SFRCS;
    								memcpy(&SFRCS, PacketData + FrameDataLength, sizeof(SFRCS));
    								SFRCS = Crc16(PacketData, FrameDataLength);
    								std::cout << "SFRCS " << std::setbase(16) <<  SFRCS << std::endl;


    								{
    									std::cout << "Received response " << Header.FDL << ":<";
//    									DebugTraceAscii(DL_Data, PacketData, Header.FDL);
    									std::cout << ">\n" << std::endl;

//    									if(PID_Counter <= Header.PID)
//    										PID_Counter = Header.PID + 1;

//    #if defined(__EGTS_CRYPTO__)
//    									uint8_t EncryptionMode = (Header.Mask_1 >> 3) & 0x03;
//
//    									if(EncryptionMode != 0)
//    									{
//    										ExtendTime_t perfEncryption = *STime.GetFullTime();
//
//    										// ���������� ���� ��� ���������� ������ ���� ������ 8
//    										uint16_t decryptedDataSize = (Header.FDL + 7) & ~0x0007;
//    										Gost28147::Decrypt(PacketData, decryptedDataSize);
//
//    										ExtendTime_t deltaEncryption = *STime.GetFullTime();
//
//    										deltaEncryption = deltaEncryption - perfEncryption;
//    										DebugModuleTrace(DL_Data, "Encryption duration: %d.%03d\n", deltaEncryption.Second, deltaEncryption.Millisecond);
//
//    										DebugModuleTrace(DL_Data, "Decrypted response %d :<", decryptedDataSize);
//    										DebugTraceAscii(DL_Data, PacketData, decryptedDataSize);
//    										DebugTrace(DL_Trace, ">\n");
//    									}
//    #endif // defined(__EGTS_CRYPTO__)

//    									Parser(&Header, PacketData);

    									std::cout << "Packet parsed successfully!" << std::endl;
    									return 0;
    								}
    							}
    						}
    					}
    				}
//    				RxBufferLevel = 0;
//    				Find_start = false;
    			}
    		}
    	}
    	return 1;
    }

    size_t read_complete(const boost::system::error_code & err, size_t bytes) {
    	std::cout << "read_complete, erc " << err << std::endl;
        if ( err) return 0;
//        bool found = std::find(read_buffer_, read_buffer_ + bytes, '\n') < read_buffer_ + bytes;
        return Parser((uint8_t *)read_buffer_, bytes);
        // we read one-by-one until we get to enter, no buffering
//        return found ? 0 : 1;
    }
private:
    ip::tcp::socket sock_;
    enum { max_msg = 1024 };
    char read_buffer_[max_msg];
    char write_buffer_[max_msg];
    bool started_;
    std::string username_;
    deadline_timer timer_;
    boost::posix_time::ptime last_ping;
    bool clients_changed_;
};

void update_clients_changed() {
    for( array::iterator b = clients.begin(), e = clients.end(); b != e; ++b)
        (*b)->set_clients_changed();
}

ip::tcp::acceptor acceptor(service, ip::tcp::endpoint(ip::tcp::v4(), 8001));

void handle_accept(talk_to_client::ptr client, const boost::system::error_code & err) {
    client->start();
    talk_to_client::ptr new_client = talk_to_client::new_();
    acceptor.async_accept(new_client->sock(), boost::bind(handle_accept,new_client,_1));
}


int main(int argc, char* argv[]) {
//	time_t currentTime;
//	time(&currentTime);
//	boost::date_time::winapi::SYSTEMTIME currentSystemTime;
//	boost::date_time::winapi::GetSystemTime(&currentSystemTime);
//	clock_t currentClock = clock();
//	char *timeString = asctime(gmtime(&currentTime));
//	std::cout << "Started at " << timeString << std::endl;
//	std::cout << "Time: " << currentTime << std::endl << "Clocks: " << currentClock << std::endl;
//	std::cout << "Api time: " << currentSystemTime.wHour << ":" << currentSystemTime.wMinute << ":" << currentSystemTime.wSecond << "." << currentSystemTime.wMilliseconds << std::endl;
	PrintTimeStamp();
    talk_to_client::ptr client = talk_to_client::new_();
    acceptor.async_accept(client->sock(), boost::bind(handle_accept,client,_1));
    std::cout << "Acceptor ok" << std::endl;
    service.run();
    std::cout << "Bye!..." << std::endl;
    return 0;
}

/****************************************************************************
 * @File nmea_agps.hpp
 *
 * @brief �������� ���������� ������ ���� � ���������� ��������� ������ � ���� ��������
 *
 * �����: ������� �.�.
 * ���� ��������: 13.03.2014
 ***************************************************************************/
//#if defined(__EGTS_SERVER)

#ifndef __EGTS_PROTOCOL_HPP
#define __EGTS_PROTOCOL_HPP

#include "time/sw_timer.hpp"
#include "server_protocol.hpp"
#include <array>

#pragma pack(push, 1)

namespace EGTS
{





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


// ��������������� ��������� ��� ����������� ������ � ������������ �������
class CacheValues
{
public:
	//! ����� ������ (� ��������� ����)
	uint16_t RecordNumber;
	//! ����� ������ (� �������)
	uint32_t HistoryRecNum;
};

/*! ��������������� ��������� ��� �������� ���������� � ����������� ��������� ������� � �������� ������ */
class ParsedRecordResult_t
{
public:
	/*! ����� ������ */
	uint16_t RecordNumber;
	/*! ��������� ��������� ������ */
	ProcessCode_t ResultCode;
};


void HistoryCallBack(RubberHistory::RecordId::HRID RecordFieldId);


class ServerEGTSProtocol : public ServerExchangeProtocol
{
	friend void HistoryCallBack(RubberHistory::RecordId::HRID RecordFieldId);
	enum class TaskEGTSState_t
	{
		/*! �������� ������ ������ */
		Idle = 0,
		StartConnectInit,			/*<! ������ �������� ��������� ���������, ����� ����������� */
		StartConnect,
		WaitConnect,				/*<! �������� ����������� � ������� */
		WaitDisconnect,				/*<! �������� ���������� �� ������� */

		Auth_TermIdent = 10,		/*<! �������� ���������� ����������� */
		Auth_TermIdentWaitAck,		/*<! �������� ������������� ����������� */

			// ����������� �������������
		Auth_TermIdentOk,			/*<! �������� ������������� ������ ����������� */
		Auth_AuthInfo,				/*<! �������� ������ ����������� ����������� */
		Auth_AuthInfoWaitAck,		/*<! �������� ������������� ����������� ����������� �� �� */
		Auth_ResultWait,			/*<! �������� ������ � ����������� ����������� */
		Auth_ResultSendAck,			/*<! �������� ������������� ���������� ����������� */

		StartOnline = 20,			/*<! ������� � ����� "�� �����" */
		Online,						/*<! ����� "�� �����" */

		DataExchange = 30,			/*<! �������� ������ �������, ������������ ������ */
		WaitDataAck,				/*<! �������� ������ �������, �������� ������������� */
		MarkSendedRecords,			/*<! ������� ���������� ������� */

		SendMFlag = 40,				/*<! �������� ������ */
		WaitMFlagClear,				/*<! �������� ������, �������� ����������� */

		ErrorExchange = 50,			/*<! ������ ��������� */
		CloseConnect,				/*<! �������� ���������� */
		WaitCloseConnect,			/*<! �������� �������� ���������� */
		Executed,					/*<! �������� ��������� �������� ������ */
	};
	struct EGTSParamsStruct
	{
		uint16_t Number;	//!< ����� ������� ��� ����������� � �������;
	};
public:
		ServerEGTSProtocol();
#if defined(__USE_DESTRUCTOR__)
		~ServerEGTSProtocol() {};
#endif // defined(__USE_DESTRUCTOR__)
	bool Binding(SerialChannel_c * PairPort);
	void Do();
	bool Executed();
	bool GetDestination(TcpConnectDestination_t *Destination, uint8_t ChannelNumber);
	void Init();
	bool IsDataReady();
	void Parser(HeaderTransport_t *PacketHeader, uint8_t *Data);
	void ParseRecord(uint8_t *SdrData, uint16_t SdrLength);
	ProcessCode_t ParseAuthServiceSubrecords(uint8_t *Data, uint16_t DataSize);
	ProcessCode_t ParseTeledataServiceSubrecords(uint8_t *Data, uint16_t DataSize);
	uint32_t Receive(const void *data, const uint32_t dataSize);
	void Reset();

	uint16_t ReadStruct(void * Data, FieldId FieldType, uint16_t FieldNumber);
	uint16_t WriteStruct(const void * Data, FieldId FieldType, uint16_t FieldNumber);

#if defined(__EGTS_STATISTIC__)
	void InitStatisticData();
#endif // defined(__EGTS_STATISTIC__)
	bool SendResponse(Service_t Service, uint16_t ConfirmedPacketID);
#if defined(__EGTS_EXTRA_AUTH__)
	bool SendAuthenticationInfo();
#endif // defined(__EGTS_EXTRA_AUTH__)

private:
	enum class ForceState
	{
		// �������������� �������� �� ���������
		ForceSend = 0,
		// ������ ����������, �������� ������������� ���������
		WaitAck,
		// �������� ���������� ����� ������� (��������)
		ForceCreateHistoryBlock,
		// �������������� �������� �������� ���������
		Executed,
	};
	enum
	{
		TASK_BUFFER_SIZE = 512,
		BUFFERED_RECORDS_NUMBER = 30,//5,
		MINIMAL_RECORD_SEND = 1,
	};

	// ���� �������� �������� ��������� �� �������
	bool IsSendOk;
	/*! ������� �������� �������� */
	uint8_t RepeateCounter;
	/*! ������������ ���������� ������� ��� �������� */
	uint8_t MaxRecordCount;
	/*! ���������� ������� ��� �������� */
	uint8_t BufferedRecordCount;
	/*! ����� � ��������� ������� ��� �������� */
	uint32_t BufferedRecordIndex[BUFFERED_RECORDS_NUMBER];

	/*! ����� ������������ ������ ��������� ������ ��������� ����� */
	uint16_t RecordNumber;

	/*! ��������� ������ */
	TaskEGTSState_t State;
	/*! ������ ������ ������ */
	SW_Timer TaskTimer;
	/*! ������ �������������� �������� ������� */
	SW_Timer ExchangeTimer;
	// ���� �������������� �������� ���� ������� ����� �����������
	ForceState ForceHistoryStatus;

	EGTSParamsStruct EGTSParams;//ServerConnectSettings.ObjectId + 10000;
	uint16_t PID_Counter;		//!< Current PID field value (EGTS transport level)

	/*! ����� �������� ��������� �� ������� */
	std::array <uint8_t, TASK_BUFFER_SIZE> RxBuffer;
	/*! ������� ������� ���������� ������ */
	uint16_t RxBufferLevel;
	/*! ������ ����� ���� ����� ������� */
	bool Find_start;
	/*! Flags witch was sent */
	uint16_t CurFlagMask;


	/*! ���� ������������� ����������� � ������� */
	bool IsConnectNeed;
	/*! ���� ������������� ������� ������ */
	bool NeverEndedTask;
	/*! ���� ������������� ��������� ������� ������ */
	bool IsCloseNeed;

#if defined(__EGTS_STATISTIC__)
	/*! ���� ������������� �������� ������ ���������� */
	bool UseStatistic;

	/*! Counter send timeout data over rtm binV2 */
	uint8_t RtmBin2_SendCounter;
	/*! Rtm binV2 target module ID for send data */
	TEmbeddedUnit RtmBin2_DestinationUnit;
	/*! Rtm binV2 target address for send data */
	uint8_t RtmBin2_DestinationAddress;
	/*! Timer for send data over rtm binV2 */
	SW_Timer RtmBin2_SendTimer;

	/*! ������� ������ ���������� */
	Statistic_t Statistic;
#endif // defined(__EGTS_STATISTIC__)


#if defined(__EGTS_CRYPTO__)
	/*! ������������� ���������� ���� 28147*/
	bool UseEncryption;
#endif // defined(__EGTS_CRYPTO__)

#if defined(__EGTS_EXTRA_AUTH__)
	/*! ������������� ����������� ����������� */
	bool UseExtendedAuthentication;
#endif // defined(__EGTS_EXTRA_AUTH__)


	// ���������� �� ������������ ������
	/*! ������������� ������ ������������� ������ */
	uint16_t CachePacketId;
	//! ���������� ������������ ������� � ������
	uint8_t CacheSdrCount;
	//! ��� ������� ������������� ������
	EGTS::Service_t CacheService;

	std::array <CacheValues, BUFFERED_RECORDS_NUMBER> SendCache;


	// ������ ����������� ��������� �������� �������
	std::array <ParsedRecordResult_t, Constants::MaxReceivedRecodsInPacket> ProcessCodes;
	uint8_t ParsedRecordCount = 0;


	void DeliveredData();
	void CheckMessage();
	void CheckTimer();
	FillResultCode FillRecordFromHistory(uint32_t RecordIndex, uint16_t MaxDataSize, RecordSSLP *OutputBuffer, uint16_t &SubrecordSize);
	FillResultCode ConvertHistoryToPosData(const uint8_t *HistoryRecord, uint16_t MaxDataSize, void *OutputBuffer, uint16_t &SubrecordSize);
	FillResultCode ConvertHistoryToExtPosData(const uint8_t *HistoryRecord, uint16_t MaxDataSize, void *OutputBuffer, uint16_t &SubrecordSize);
	FillResultCode ConvertHistoryToLiquidSensor(const uint8_t *HistoryRecord, uint16_t MaxDataSize, void *OutputBuffer, uint16_t &SubrecordSize);

	FillResultCode FillSubrecordIdentity(uint16_t MaxDataSize, void *OutputBuffer, uint16_t &SubrecordSize);
	FillResultCode FillSubrecordLoopin(uint16_t SubrecordFlagMask, uint16_t MaxDataSize, void *OutputBuffer, uint16_t &SubrecordSize);

	clock_t ConvertTime(clock_t time = 0);

	bool ErrorExecute();


	bool SendIdent();
	bool SendHistory();
	bool SendMFlag();
	uint16_t TransportForming(TransportPacket_t *OutgoingPacketBuffer,
			Transport::PacketType PacketType,
			uint16_t SDR_size );

	bool SendPacket(TransportPacket_t *OutgoingPacketBuffer, Transport::PacketType PacketType, uint16_t RecordsDataSize);

#if defined(__EGTS_STATISTIC__)
	FillResultCode FillRecordCommonStatistic(uint16_t MaxDataSize, RecordSSLP *OutputBuffer, uint16_t &RecordSize);
	FillResultCode FillRecordStatistic(uint16_t MaxDataSize, void *OutputBuffer, uint16_t &SubrecordSize);
	void SendParamsToBin2();
#endif // defined(__EGTS_STATISTIC__)
};


void HistoryCallBack(RubberHistory::RecordId::HRID RecordFieldId);

extern ServerEGTSProtocol EGTSProtocol;


} // namespace EGTS

#pragma pack(pop)

#endif // __EGTS_PROTOCOL_HPP

//#endif // defined(__EGTS_SERVER)

/****************************************************************************
*								����� �����									*
****************************************************************************/

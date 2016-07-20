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
	 * Данный тип сервиса применяется для осуществления процедуры аутентификации АС (авторизуемой ТП) на авторизующей ТП.
	 * При использовании TCP/IP протокола в качестве транспорта, АС (авторизуемая ТП) должна  проходить данную  процедуру, и только после успешного завершения данной процедуры происходит дальнейшее взаимодействие.
	 */
	AUTH_SERVICE = 1,

	/**
	 * Сервис предназначен для обработки телематической информации (координатные данные, данные о срабатывании датчиков и т.д.), поступающей от АС.
	 * Сервис описан в отдельном документе
	 */
	TELEDATA_SERVICE = 2,

	/**
	 * Данный тип сервиса предназначен для обработки управляющих и конфигурационных команд, информационных сообщений и статусов, передаваемых между АС, ТП и операторами
	 */
	COMMANDS_SERVICE = 4,

	/**
	 * Сервис предназначен для передачи на АС конфигурации и непосредственно самого программного обеспечения (ПО) аппаратной части самого АС, а также различного периферийного оборудования, подключенного к АС и поддерживающеговозможность удалённого обновления ПО
	 */
	FIRMWARE_SERVICE = 9,

	/**
	 * Сервис, обеспечивающий выполнение функционала ЭРА.
	 * Сервис описан в отдельном документе
	 */
	ECALL_SERVICE = 10,
};


/*! Формат подзаписи подтверждения - универсальный для всех сервисов (AUTH_SERVICE, TELEDATA_SERVICE) */
struct SR_RECORD_RESPONSE
{
	//! Номер подтверждаемой записи
	uint16_t ConfirmedRecordNumber;
	//! Статус обработки записи
	uint8_t RecordStatus;
};

namespace AUTH_SERVICE
{
namespace SubrecordType
{
	enum Enum
	{
		EGTS_SR_RECORD_RESPONSE = 0,	//Подзапись применяется для осуществления подтверждения процесса обработки записи Протокола Уровня Поддержки Услуг. Данный тип подзаписи должен поддерживаться всеми Сервисами
		EGTS_SR_TERM_IDENTITY = 1,	//Подзапись используется только АС при запросе авторизации на авторизующей ТП и содержит учётные данные АС
		EGTS_SR_MODULE_DATA = 2,	//Подзапись предназначена для передачи на ТП информации об инфраструктуре на стороне АС, о составе, состоянии и параметрах блоков и модулей АС. Данная подзапись является опциональной, и разработчик АС сам принимает решение о необходимости заполнения полей и отправки данной подзаписи. Одна подзапись описывает один модуль. В одной записи может передаваться последовательно несколько таких подзаписей, что позволяет передать данные об отдельных составляющих всей аппаратной части АС и периферийного оборудования
		EGTS_SR_VEHICLE_DATA = 3,	//Подзапись применяется АС для передачи на ТП информации о транспортном средстве.
		EGTS_SR_DISPATCHER_IDENTITY = 5,	//Подзапись используется только авторизуемой ТП при запросе авторизации на авторизующей ТП и содержит учётные данные авторизуемой АС
		EGTS_SR_AUTH_PARAMS = 6,	//Подзапись используется авторизующей ТП для передачи на АС данных о способе и параметрах шифрования, требуемого для дальнейшего взаимодействия
		EGTS_SR_AUTH_INFO = 7, 	//Подзапись предназначена для передачи на авторизующую ТП аутентификационных данных АС (авторизуемой ТП) с использованием ранее переданных со стороны авторизующей ТП параметров для осуществления шифрования данных
		EGTS_SR_SERVICE_INFO = 8,	//Данный тип подзаписи используется для информирования принимающей стороны, АС или ТП, в зависимости от направления отправки, о поддерживаемых Сервисах, а также для запроса определённого набора требуемых Сервисов (от АС к ТП)
		EGTS_SR_RESULT_CODE= 9	//Подзапись применяется авторизующей ТП для информирования АС (авторизуемой ТП) о результатах процедуры аутентификации АС
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
	// необязательные параметры - не поддерживаются
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
		//! Подзапись применяется для осуществления подтверждения приёма и передачи результатов обработки записи Уровня Поддержки Услуг
		RECORD_RESPONSE = 0,

		//! Подзапись используется АТ при передаче основных данных определения местоположения
		POS_DATA = 16,

		//! Подзапись используется АТ при передаче дополнительных данных определения местоположения
		EXT_POS_DATA = 17,

		//! Подзапись  применяется АТ  для передачи на ТП информации о состоянии дополнительных дискретных и аналоговых входов
		AD_SENSORS_DATA = 18,

		//! Подзапись  используется ТП для передачи на АТ данных о значении счётных входов
		COUNTERS_DATA = 19,

		//! Подзапись предназначена для передачи на ТП данных профиля ускорения АТ
		ACCEL_DATA = 20,

		//! Данный тип подзаписи используется для передачи на ТП информации о состоянии АТ (текущий режим работы, напряжение основного и резервного источников питания и т.д.)
		STATE_DATA = 21,

		//! Подзапись применяется АТ для передачи на ТП данных о состоянии шлейфовых входов (используемых в охранных системах)
		LOOPIN_DATA = 22,

		//! Подзапись применяется АТ для передачи на ТП данных о состоянии одного дискретного входа
		ABS_DIG_SENS_DATA = 23,

		//! Подзапись  применяется  АТ для передачи на ТП данных о состоянии одного аналогового входа
		ABS_AN_SENS_DATA = 24,

		//! Подзапись применяется АТ для передачи на ТП данных о состоянии одного счётного входа
		ABS_CNTR_DATA = 25,

		//! Подзапись применяется АТ для передачи на ТП данных о состоянии одного шлейфового входа
		ABS_LOOPIN_DATA = 26,

		//! Подзапись применяется АТ для передачи на ТП данных о показаниях ДУЖ
		LIQUID_LEVEL_SENSOR = 27,

		//! Подзапись применяется АТ для передачи на ТП данных о показаниях счетчиков пассажиропотока
		PASSENGERS_COUNTERS = 28,
	};
} // namespace SubrecordType

typedef struct EGTS::SR_RECORD_RESPONSE SR_RECORD_RESPONSE;
} // namespace TELEDATA





struct __attribute__ ((__packed__)) RDStruct
{
	/**
	 * Subrecord Type
	 * Тип подзаписи (подтип передаваемых данных в рамках общего набора типов одного Сервиса).
	 * Тип 0 – специальный, зарезервирован за подзаписью подтверждения данных для каждого сервиса.
	 * Конкретные значения номеров типов подзаписей определяются логикой самого Сервиса.
	 * Протокол оговаривает лишь то, что этот номер должен присутствовать, а нулевой идентификатор зарезервирован
	 */
	uint8_t SRT;

	/**
	 * Subrecord Length
	 * Длина данных в байтах подзаписи в поле SRD
	 */
	uint16_t SRL;

	/**
	 * Subrecord Data (0…65495)
	 * Данные подзаписи.
	 * Наполнение данного поля специфично для каждого сочетания идентификатора типа Сервиса и типа подзаписи
	 */
	uint8_t SRD[];
};

struct __attribute__ ((__packed__)) TELEDATA_SERVICE_POS_DATAStruct
{
	/*! Общий заголовок подзаписи */
	RDStruct Header;
	/**
	 * Время навигации (количество секунд с 00:00:00 01.01.2010 UTC)
	 */
	uint32_t NTM;

	/**
	 * Широта по модулю, градусы / 90 * 0xFFFFFFFF и взята целая часть
	 */
	uint32_t LAT;

	/**
	 * Долгота по модулю, градусы / 180 * 0xFFFFFFFF и взята целая часть
	 */
	uint32_t LONG;

	/**
	* FLG битовые флаги (ALTE, LOHS, LAHS, MV, BB, FIX, CS, VLD)
	* FLG[7] ALTE наличие поля ALT в подзаписи: 1 - поле ALT передается; 0 - не передаётся
	* FLG[6] LOHS полушарие долготы: 0 - восточная долгота; 1 - западная долгота
	* FLG[5] LAHS полушарие широты: 0 - северная широта; 1 - южная широта
	* FLG[4] MV признак движения: 1 - движение; 0 - АТ находится в режиме стоянки
	* FLG[3] BB признак отправки данных из памяти («чёрный ящик»): 0 - актуальные данные; 1 - данные из памяти («чёрного ящика»)
	* FLG[2] FIX тип определения координат: 0 - 2D fix; 1 - 3D fix
	* FLG[1] CS тип используемой системы: 0 - WGS-84; 1 - ПЗ-90.02
	* FLG[0] VLD признак «валидности» координатных данных: 1 - данные «валидны»; 0 - «невалидные» данные
	*/
	uint8_t FLG;

	/**
	* SPD (DIRH, ALTS, SPD[0:13])
	* SPD[15] DIRH (Direction the Highest bit) старший бит параметра DIR
	* SPD[14] ALTS (Altitude Sign) битовый флаг, определяет высоту относительно уровня моря и имеет смысл только при установленном флаге ALTE
	* SPD[0:13] скорость в десятых долях миль/ч (используется 14 младших бит)
	*/
	uint16_t SPD;

	/**
	 * DIR направление движения.
	 * Определяется как угол в градусах, который отсчитывается по часовой стрелке между северным направлением географического меридиана и направлением движения в точке измерения (дополнительно старший бит находится в поле DIRH)
	 */
	uint8_t DIR;

	/**
	 * ODM пройденное расстояние (пробег) в десятых долях километра
	 */
	uint8_t ODM[3];

	/**
	 * DIN битовые флаги, определяют состояние основных дискретных входов 1…8 (если бит равен 1, то соответствующий вход активен, если 0 - неактивен).
	 * Данное поле включено для удобства использования и экономии трафика при работе в системах мониторинга транспорта базового уровня
	 */
	uint8_t DIN;

	/**
	 * SRC определяет источник (событие), инициировавший посылку данной навигационной информации
	 */
	uint8_t SRC;
};


struct __attribute__ ((__packed__)) TELEDATA_SERVICE_EXT_POS_DATAStruct
{
	/*! Общий заголовок подзаписи */
	RDStruct Header;

	/**
	* Flags битовые флаги (ALTE, LOHS, LAHS, MV, BB, FIX, CS, VLD)
	* Flags[4] NSFE наличие поля NS: 1 - поле передается; 0 - не передается
	* Flags[3] SFE наличие полей SAT и NS: 1 - поля передаются; 0 - не передаются
	* Flags[2] PFE наличие поля PDOP: 1 - поле передается; 0 - не передается
	* Flags[1] HFE наличие поля HDOP: 1 - поле передается; 0 - не передается
	* Flags[0] VFE наличие поля VDOP: 1 - поле передается; 0 - не передается
	*/
	uint8_t Flags;

	/**
	 * Снижение точности в вертикальной плоскости (значение, умноженное на 100)
	 */
	uint16_t VDOP;

	/**
	 * Снижение точности в горизонтальной плоскости (значение, умноженное на 100)
	 */
	uint16_t HDOP;

	/**
	 * Снижение точности по местоположению (значение, умноженное на 100)
	 */
	uint16_t PDOP;

	/**
	* Количество видимых спутников.
	*/
	uint8_t SAT;

	/**
	* Количество видимых спутников, битовая маска. 0 - система не определена
	* Flags[7] QZSS
	* Flags[6] IRNSS
	* Flags[5] Doris
	* Flags[4] Beidou
	* Flags[3] Compass
	* Flags[2] Galileo
	* Flags[1] GPS
	* Flags[0] ГЛОНАСС
	*/
	uint16_t NS;
};


struct __attribute__ ((__packed__)) TELEDATA_SERVICE_LOOPIN_DATAStruct
{
	/*! Общий заголовок подзаписи */
	RDStruct Header;

	/**
	 * 	LIFE1…LIFE8	– (Loop In Field Exists) битовые флаги, определяющие наличие информации
	 * о состоянии шлейфовых входов. Например, если необходимо передать данные от ШВ 1, 3, 8, после 1 байта,
	 * содержащего битовые флаги LIFE1=1, LIFE3=1 и LIFE8=1, будет передан один байт,
	 * содержащий информацию о состоянии ШВ 1 и 3, один байт, содержащий информацию о состоянии ШВ 8 (младшие 4 бита);
	 */
	uint8_t LIFE;

	/**
	 * LIS n … LIS n+7	– (Loop In State) значение состояния соответствующего шлейфового входа.
	 * Полубайтовые значения.
	 * Предусмотрены следующие состояния шлейфового входа (бинарное представление):
	 *	0000 = «норма»;
	 *	0001 = «тревога»;
	 *	0010 = «обрыв»;
	 *	0100 = «замыкание на землю»;
	 *	1000 = «замыкание на питание».
	 */
	uint8_t LIS[4];
};


struct __attribute__ ((__packed__)) TELEDATA_SERVICE_ABS_CNTR_DATA_Struct
{
	/*! Общий заголовок подзаписи */
	RDStruct Header;

	/**
	 *	Номер счетного входа
	 */
	uint8_t CounterNumber;

	/**
	 *	Показания счетного входа
	 */
	uint8_t CounterValue[3];
};


struct __attribute__ ((__packed__)) TELEDATA_SERVICE_LIQUID_LEVEL_SENSORStruct
{
	/*! Общий заголовок подзаписи */
	RDStruct Header;

	/**
	* Flags битовые флаги (ALTE, LOHS, LAHS, MV, BB, FIX, CS, VLD)
	* Flags[6] LLSEF наличие ошибок при считывании значения датчика: 1 - ошибка при считывании показаний; 0 - ошибок не обнаружено
	* Flags[5:4] LLSVU единицы измерений показания ДУЖ
	* 			00 - нетарированное показания датчика
	* 			01 - показания в % от общего объема
	* 			10 - показания с дискретностью 0,1 л
	* Flags[3] RDF - флаг не приведенного формата данных.
	* 		0 - показания размером 4 байта, 1 - показания размером 4..512
	* 		используем всегда 0
	* Flags[2:0] LLSN порядковый номер датчика
	*/
	uint8_t Flags;

	/**
	 *	адрес модуля, данные о показаниях ДУЖ с которого поступили в АТ (номер внешнего порта АТ)
	 */
	uint16_t MADDR;

	/**
	 *	показания ДУЖ
	 */
	uint32_t LLSD;
};


struct __attribute__ ((__packed__)) AUTH_SERVICE_TERM_IDENTITYStruct
{
	/*! Общий заголовок подзаписи */
	RDStruct Header;

	/**
	 * (Terminal Identifier), уникальный идентификатор, назначаемый при программировании АС.
	 * Наличие значения 0 в данном поле означает, что АС не прошел процедуру конфигурирования,
	 * или прошел её не полностью. Данный идентификатор назначается оператором и однозначно
	 * определяет набор учетных данных АС. TID назначается при инсталляции АС как дополнительного
	 * оборудования и передаче оператору учетных данных АС (IMSI, IMEI, serial_id).
	 * В случае использования АС в качестве штатного устройства, TID сообщается оператору
	 * автопроизводителем вместе с учетными данными (VIN, IMSI, IMEI);
	 */
	uint32_t TID;

	/**
	* FLG битовые флаги (MNE, BSE, NIDE, SSRA, LNGCE, IMSIE, IMEIE, HDIDE)
	* FLG[7] MNE – (Mobile Network Exists), битовый флаг, определяющий наличие поля MSISDN в подзаписи (если бит равен 1, то поле передаётся, если 0, то не передаётся);
	* FLG[6] BSE – (Buffer Size Exists), битовый флаг, определяющий наличие поля BS в подзаписи (если бит равен 1, то поле передаётся, если 0, то не передаётся);
	* FLG[5] NIDE - (Network Identifier Exists), битовый флаг определяет наличие поля NID в подзаписи (если бит равен 1, то поле передаётся, если 0, то не передаётся);
	* FLG[4] SSRA – битовый флаг предназначен для определения алгоритма использования Сервисов (если бит равен 1, то используется «простой» алгоритм, если 0, то алгоритм «запросов» на использование Cервисов);
	* FLG[3] LNGCE – (Language Code Exists), битовый флаг, который определяет наличие поля LNGC в подзаписи (если бит равен 1, то поле передаётся, если 0, то не передаётся);
	* FLG[2] IMSIE – (International Mobile Subscriber Identity Exists), битовый флаг, который определяет наличие поля IMSI в подзаписи (если бит равен 1, то поле передаётся, если 0, то не передаётся);
	* FLG[1] IMEIE – (International Mobile Equipment Identity Exists), битовый флаг,  который определяет наличие поля IMEI в подзаписи (если бит равен 1, то поле передаётся, если 0, то не передаётся);
	* FLG[0] HDIDE – (Home Dispatcher Identifier Exists), битовый флаг, который определяет наличие поля HDID в подзаписи (если бит равен 1, то поле передаётся, если 0, то не передаётся);
	*/
	uint8_t FLG;

	/**
	 * (Home Dispatcher Identifier), идентификатор «домашней» ТП (подробная учётная
	 * информация о терминале хранится на данной ТП);
	 */
	uint16_t HDID;

	/**
	 * (International Mobile Equipment Identity), идентификатор мобильного устройства (модема).
	 * При невозможности определения данного параметра, АС должна заполнять данное поле
	 * значением 0 во всех 15-ти символах;
	 */
	char IMEI[15];

	/**
	 * (International Mobile Subscriber Identity), идентификатор мобильного абонента.
	 * При невозможности определения данного параметра, АС должна заполнять данное поле
	 * значением 0 во всех 16-ти символах;
	 */
	//char IMSI[16];

	/**
	 * (Language Code), код языка, предпочтительного к использованию на стороне АС, по ISO 639-2,
	 * например, «rus» – русский;
	 */
	//char LNGC[3];

	/**
	 * (Network Identifier), идентификатор сети оператора, в которой зарегистрирована АС на данный момент.
	 * Используются 20 младших бит. Представляет пару кодов MCC-MNC (на основе рекомендаций ITU-T E.212).
	 */
	//uint8_t NID[3];

	/**
	 * (Buffer Size), максимальный размер буфера приёма АС в байтах. Размер каждого пакета информации,
	 * передаваемого на АС, не должен превышать данного значения. Значение поля BS может принимать
	 * различные значения, например 800, 1000, 1024, 2048, 4096 и т.д., и зависит от реализации
	 * аппаратной и программной частей конкретной АС;
	 */
	//uint16_t BS;

	/**
	 * (Mobile Station Integrated Services Digital Network Number), телефонный номер мобильного абонента.
	 * При невозможности определения данного параметра, устройство должно заполнять данное поле значением 0
	 * во всех 15-ти символах
	 */
	//char MSISDN[15];
};


/*! Структура минимального заголовка отдельной записи протокола уровня поддержки услуг */
struct HeaderSdrMinimal_t
{
	/*! Размер данных */
	uint16_t RL;
	/*! Номер записи */
	uint16_t RN;

	/*! Флаги описания записи. [7] SSOD (1), [6] RSOD, [5] GRP, [3:4] RPP, [2] TMFE (1), [1] EVFE, [0] OBFE (1)*/
	uint8_t RFL;

	// Минимальный размер обязательных данных - 5 байт, необязательные поля добавляются перед
	// обязательными и могут менять назначение байт в заголовке
	uint8_t data[2];
};


/*! Структура заголовка отдельной записи протокола уровня поддержки услуг */
struct HeaderSDR_t
{
	/*! Размер данных */
	uint16_t RL;
	/*! Номер записи */
	uint16_t RN;

	/*! Флаги описания записи - используется 0x85. [7] SSOD (1), [6] RSOD, [5] GRP, [3:4] RPP, [2] TMFE (1), [1] EVFE, [0] OBFE (1)*/
	uint8_t RFL;
	/*! Идентификатор объекта (используется 2 байта из 4-х) */
	uint32_t OID;
	/*! Время формирования записи */
	uint32_t TM;
	/*! Идентификатор типа Сервиса-отправителя */
	Service_t SST;
	/*! Идентификатор типа Сервиса-получателя */
	Service_t RST;
};


/*! Структура подзаписи Протокола Уровня Поддержки Услуг */
struct SubrecordSSLP
{
	/*! Заголовок подзаписи */
	RDStruct Header;
	/*! Набор данных подзаписи */
	uint8_t Data[];
};


/*! Структура отдельной записи Протокола Уровня Поддержки Услуг */
struct RecordSSLP
{
	/*! Заголовок записи */
	HeaderSDR_t Header;
	/*! Набор подзаписей */
	SubrecordSSLP Subrecord[];
};


struct Response_t
{
	/*! Идентификатор пакета транспортного уровня */
	uint16_t RPID;
	/*! Код результатат обработки пакета */
	uint8_t PR;
};


/*! Структура заголовка пакета транспортного уровня */
struct HeaderTransport_t
{
	/*! Версия протокола - используется 1 */
	uint8_t PRV;
	/*! Идентификатор ключа, используемый при шифровании - используется 0 при отсутствии шифрования или 1 для ГОСТ 28147 */
	uint8_t SKID;

	/*! PRF[0:1] (Prefix), RTE, ENA[0:1], CMP, PR[0:1] - используется 0 */
	uint8_t Mask_1;

	/*! Длина заголовка Транспортного Уровня в байтах с учётом байта контрольной суммы (поля HCS) - 11 байт */
	uint8_t HL;
	/* Резерв */
	uint8_t HE;
	/*! Размер в байтах поля данных SFRD, содержащего информацию Протокола Уровня Поддержки Услуг */
	uint16_t FDL;	// = sizeof(HeaderSDR_t) + SDR_size;
	/*! Номер пакета Транспортного Уровня*/
	uint16_t PID;
	/*! Тип пакета */
	Transport::PacketType PT;
	/*! Контрольная сумма заголовка Транспортного Уровня */
	uint8_t HCS;
};


/*! Структура пакета транспортного уровня */
struct TransportPacket_t
{
	/*! Заголовок транспортного уровня */
	HeaderTransport_t Header;
	/*! Данные записей */
	RecordSSLP Record[];
};




// Прочие константы
namespace Constants
{
#if defined(__EGTS_STATISTIC__)
	/*! Количество поддерживаемых счетчиков статистики ЕГТС */
	extern const uint32_t StatisticNumber;
#endif // defined(__EGTS_STATISTIC__)
	enum
	{
		MaxReceivedRecodsInPacket = 10,
	};
}

enum ProcessCode_t
{
	OK = 0, //!< Успешно обработано
	IN_PROGRESS = 1, //!< В процессе обработки (результат обработки ещё не известен)
	UNS_PROTOCOL = 128, //!< Неподдерживаемый протокол
	DECRYPT_ERROR = 129, //!< Ошибка декодирования
	PROC_DENIED = 130, //!< Обработка запрещена
	INC_HEADERFORM = 131, //!< Неверный формат заголовка
	INC_DATAFORM = 132, //!< Неверный формат данных
	UNS_TYPE = 133, //!< Неподдерживаемый тип
	NOTEN_PARAMS = 134, //!< Неверное количество параметров
	DBL_PROC = 135, //!< Попытка повторной обработки
	PROC_SRC_DENIED = 136, //!< Обработка данных от источника запрещена
	HEADERCRC_ERROR = 137, //!< Ошибка контрольной суммы заголовка
	DATACRC_ERROR = 138, //!< Ошибка контрольной суммы данных
	INVDATALEN = 139, //!< Некорректная длина данных
	ROUTE_NFOUND = 140, //!< Маршрут не найден
	ROUTE_CLOSED = 141, //!< Маршрут закрыт
	ROUTE_DENIED = 142, //!< Маршрутизация запрещена
	INVADDR = 143, //!< Неверный адрес
	TTLEXPIRED = 144, //!< Превышено количество ретрансляции данных
	NO_ACK = 145, //!< Нет подтверждения
	OBJ_NFOUND = 146, //!< Объект не найден
	EVNT_NFOUND = 147, //!< Событие не найдено
	SRVC_NFOUND = 148, //!< Сервис не найден
	SRVC_DENIED = 149, //!< Сервис запрещён
	SRVC_UNKN = 150, //!< Неизвестный тип сервиса
	AUTH_DENIED = 151, //!< Авторизация запрещена
	ALREADY_EXISTS = 152, //!< Объект уже существует
	ID_NFOUND = 153, //!< Идентификатор не найден
	INC_DATETIME = 154, //!< Неправильная дата и время
	IO_ERROR = 155, //!< Ошибка ввода/вывода
	NO_RES_AVAIL = 156, //!< Недостаточно ресурсов
	MODULE_FAULT = 157, //!< Внутренний сбой модуля
	MODULE_PWR_FLT = 158, //!< Сбой в работе цепи питания модуля
	MODULE_PROC_FLT = 159, //!< Сбой в работе микроконтроллера модуля
	MODULE_SW_FLT = 160, //!< Сбой в работе программы модуля
	MODULE_FW_FLT = 161, //!< Сбой в работе внутреннего ПО модуля
	MODULE_IO_FLT = 162, //!< Сбой в работе блока ввода/вывода модуля
	MODULE_MEM_FLT = 163, //!< Сбой в работе внутренней памяти модуля
	TEST_FAILED = 164, //!< Тест не пройден
};


/*! Структура пакета транспортного уровня */
struct TransportPacket_t;
/*! Структура заголовка пакета транспортного уровня */
struct HeaderTransport_t;
/*! Структура отдельной записи Протокола Уровня Поддержки Услуг */
struct RecordSSLP;
/*! Структура заголовка отдельной записи протокола уровня поддержки услуг */
struct HeaderSDR_t;
/*! Структура подзаписи Протокола Уровня Поддержки Услуг */
struct SubrecordSSLP;

enum class Service_t : uint8_t;

#if defined(__EGTS_STATISTIC__)
struct Statistic_t
{
	/*! CN = 100, Количество всех подтвержденных записей, переданных на сервер
	 * на момент формирования пакета EGTS_TELEDATA_SERVICE */
	uint32_t TotalConfirmed;
	/*! CN = 101, Количество всех потерянных записей, т.е. непереданные записи, которые были затерты новыми */
	uint32_t Unsent;
	/*! CN = 102, Количество соединений с сервером */
	uint32_t ConnectCounter;
};
#endif // defined(__EGTS_STATISTIC__)



/*! Коды возврата функции формирования записи/подзаписи */
enum class FillResultCode
{
	Normal = 0,
	WrongRecord = 1,
	BufferFull = 2,
};

/*! Типы данных с доступом по протоколу RTM */
enum class FieldId
{
	/*! Разрешение работы алгоритма сбора/передачи статистики ЕГТС */
	StatisticEnable = 0,
	/*! Состав статистики - количество счетчиков */
	StatisticContent,
	/*! Значение счетчиков */
	StatisticValue,
	/*! Запрос на получение данных статистики */
	SendCommand,

	/// Разрешение использования шифрования при обмене с сервером
	CryptoEnable,
	/// Ключ шифрования по ГОСТ 28147
	CryptoKey,
	/// Таблица подстановки по ГОСТ 28147
	CryptoTable,
};















namespace Timeout
{
	/*! Время ожидания закрытия канала */
		const uint32_t ChannelClose = 30000;

	/*! Максимальное время ожидания подключения к серверу (установление канала связи) */
#if defined(__SIM_RESERVED__)
	const uint32_t MAX_SERVER_CONNECTION_TIME = 900000;
#else
	const uint32_t MAX_SERVER_CONNECTION_TIME = 300000;
#endif // defined(__SIM_RESERVED__)

	/*! Время ожидания при повторе неудачной передачи пакета */
	const uint32_t RETRY_TIMEOUT = 10000;

	/*! Таймаут принудительной отправки данных */
	const uint32_t FORCE_SEND_TIMEOUT = 120000;

	/*! Таймаут ожидания подтверждения передачи пакета */
	// TODO deprecated - замена на TL_RESPONSE_TO
	const uint32_t RESPONSE_TIMEOUT = 30000;

	/*! Максимальное время задачи при отсутствии обмена */
	const uint32_t EXCHANGE_INACTIVE_TIMEOUT = 600000;

	/*! Таймаут отправки пакетов по rtm_binV2 */
	const uint32_t SEND_BIN2_PERIOD = 1000;



	/// Константы из документации на протокол ЕГТС
	/*! Время ожидания подтверждения пакета */
	const uint32_t TL_RESPONSE_TO = 10000;

	/*! Время на авторизацию */
	const uint32_t EGTS_SL_NOT_AUTH_TO = 600; //6;
} // namespace Timeout

namespace Strings
{

} // namespace Strings

// Прочие константы
namespace Constants
{
	/// Текущая версия протокола ЕГТС
	const uint8_t ProtocolVersion = 1;

	/*! Количество попыток отправки пакета авторизации */
	const uint8_t AuthenticationRetry = 3;

	/*! Количество попыток отправки пакета данных или тревог */
	const uint8_t DataSendRetry = 5;

	/*! Количество попыток закрытия соединения */
	const uint32_t ChannelCloseRetry = 10;

	const clock_t BaseTimeStamp = 1262304000; // POSIX time 0h0m0s, 01.01.2010 UTC

#if defined(__EGTS_STATISTIC__)
	/*! Количество поддерживаемых счетчиков статистики ЕГТС */
	const uint32_t StatisticNumber = 7;
#endif // defined(__EGTS_STATISTIC__)

	/// Размер поля SFRCS пакета транспортного уровня
	const uint8_t SFRCSLength = 2;


	const char DefaultUserName[] = "Voyager";
	const char DefaultUserPassword[] = "12345678";


	/// Константы из документации на протокол ЕГТС
	/*! Количество попыток повторной отправки пакета транспортного уровня после отсутсвия ответа */
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
    								// SFRD (для APP_DATA), RPID (для APP_RESPONSE)
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
//    										// Количество байт для шифрования должно быть кратно 8
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

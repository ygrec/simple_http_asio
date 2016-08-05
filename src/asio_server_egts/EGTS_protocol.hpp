/****************************************************************************
 * @File nmea_agps.hpp
 *
 * @brief Описание интерфейса задачи ЕГТС и интерфейса протокола обмена с ЕГТС сервером
 *
 * Автор: Егоркин С.В.
 * Дата создания: 13.03.2014
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


// Вспомагательная структура для кеширования данных о передаваемых записях
class CacheValues
{
public:
	//! Номер записи (в протоколе ЕГТС)
	uint16_t RecordNumber;
	//! Номер записи (в истории)
	uint32_t HistoryRecNum;
};

/*! Вспомагательная структура для хранения информации о результатах обработки записей в принятом пакете */
class ParsedRecordResult_t
{
public:
	/*! Номер записи */
	uint16_t RecordNumber;
	/*! Результат обработки записи */
	ProcessCode_t ResultCode;
};


void HistoryCallBack(RubberHistory::RecordId::HRID RecordFieldId);


class ServerEGTSProtocol : public ServerExchangeProtocol
{
	friend void HistoryCallBack(RubberHistory::RecordId::HRID RecordFieldId);
	enum class TaskEGTSState_t
	{
		/*! Ожидание начала задачи */
		Idle = 0,
		StartConnectInit,			/*<! Запуск автомата обработки протокола, старт подключения */
		StartConnect,
		WaitConnect,				/*<! Ожидание подключения к серверу */
		WaitDisconnect,				/*<! Ожидание отключения от сервера */

		Auth_TermIdent = 10,		/*<! Отправка информации авторизации */
		Auth_TermIdentWaitAck,		/*<! Ожидание подтверждения авторизации */

			// Расширенная идентификация
		Auth_TermIdentOk,			/*<! Получено подтверждение пакета авторизации */
		Auth_AuthInfo,				/*<! Отправка данных расширенной авторизации */
		Auth_AuthInfoWaitAck,		/*<! Ожидание подтверждения расширенной авторизации на ТП */
		Auth_ResultWait,			/*<! Ожидание пакета с результатом авторизации */
		Auth_ResultSendAck,			/*<! Отправка подтверждения результата авторизации */

		StartOnline = 20,			/*<! Переход в режим "На связи" */
		Online,						/*<! Режим "На связи" */

		DataExchange = 30,			/*<! Отправка данных истории, формирование пакета */
		WaitDataAck,				/*<! Отправка данных истории, ожидание подтверждения */
		MarkSendedRecords,			/*<! Отметка переданных записей */

		SendMFlag = 40,				/*<! Отправка тревог */
		WaitMFlagClear,				/*<! Отправка тревог, ожидание подключения */

		ErrorExchange = 50,			/*<! Ошибка протокола */
		CloseConnect,				/*<! Закрытие соединения */
		WaitCloseConnect,			/*<! Ожидание закрытия соединения */
		Executed,					/*<! Протокол корректно завершил работу */
	};
	struct EGTSParamsStruct
	{
		uint16_t Number;	//!< Номер объекта при подключении к серверу;
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
		// Принудительная отправка не выполнена
		ForceSend = 0,
		// Данные отправлены, ожидание подтверждения получения
		WaitAck,
		// Отправка последнего блока истории (неполный)
		ForceCreateHistoryBlock,
		// Принудительная отправка выполена полностью
		Executed,
	};
	enum
	{
		TASK_BUFFER_SIZE = 512,
		BUFFERED_RECORDS_NUMBER = 30,//5,
		MINIMAL_RECORD_SEND = 1,
	};

	// Флаг успешной доставки сообщения до сервера
	bool IsSendOk;
	/*! Счетчик повторов передачи */
	uint8_t RepeateCounter;
	/*! Максимальное количество записей для передачи */
	uint8_t MaxRecordCount;
	/*! Количество записей для отправки */
	uint8_t BufferedRecordCount;
	/*! Буфер с индексами записей для передачи */
	uint32_t BufferedRecordIndex[BUFFERED_RECORDS_NUMBER];

	/*! Номер передаваемой записи протокола Уровня Поддержки Услуг */
	uint16_t RecordNumber;

	/*! Состояние задачи */
	TaskEGTSState_t State;
	/*! Таймер работы задачи */
	SW_Timer TaskTimer;
	/*! Таймер принудительной передачи записей */
	SW_Timer ExchangeTimer;
	// Флаг принудительной передачи всей истории после подключения
	ForceState ForceHistoryStatus;

	EGTSParamsStruct EGTSParams;//ServerConnectSettings.ObjectId + 10000;
	uint16_t PID_Counter;		//!< Current PID field value (EGTS transport level)

	/*! Буфер принятых сообщений от сервера */
	std::array <uint8_t, TASK_BUFFER_SIZE> RxBuffer;
	/*! Текущий уровень заполнения буфера */
	uint16_t RxBufferLevel;
	/*! Пойман старт идет прием посылки */
	bool Find_start;
	/*! Flags witch was sent */
	uint16_t CurFlagMask;


	/*! Флаг необходимости подключения к серверу */
	bool IsConnectNeed;
	/*! Флаг бесконечности текущей задачи */
	bool NeverEndedTask;
	/*! Флаг необходимости заверения текущей задачи */
	bool IsCloseNeed;

#if defined(__EGTS_STATISTIC__)
	/*! Флаг необходимости передачи данных статистики */
	bool UseStatistic;

	/*! Counter send timeout data over rtm binV2 */
	uint8_t RtmBin2_SendCounter;
	/*! Rtm binV2 target module ID for send data */
	TEmbeddedUnit RtmBin2_DestinationUnit;
	/*! Rtm binV2 target address for send data */
	uint8_t RtmBin2_DestinationAddress;
	/*! Timer for send data over rtm binV2 */
	SW_Timer RtmBin2_SendTimer;

	/*! Текущие данные статистики */
	Statistic_t Statistic;
#endif // defined(__EGTS_STATISTIC__)


#if defined(__EGTS_CRYPTO__)
	/*! Использование шифрования ГОСТ 28147*/
	bool UseEncryption;
#endif // defined(__EGTS_CRYPTO__)

#if defined(__EGTS_EXTRA_AUTH__)
	/*! Использование расширенной авторизации */
	bool UseExtendedAuthentication;
#endif // defined(__EGTS_EXTRA_AUTH__)


	// Информация об отправленном пакете
	/*! Идентификатор пакета транспортного уровня */
	uint16_t CachePacketId;
	//! Количество отправленных записей в пакете
	uint8_t CacheSdrCount;
	//! Тип сервиса отправленного пакета
	EGTS::Service_t CacheService;

	std::array <CacheValues, BUFFERED_RECORDS_NUMBER> SendCache;


	// Массив результатов обработки принятых записей
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
*								Конец файла									*
****************************************************************************/

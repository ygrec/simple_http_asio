 	 /****************************************************************************
 * @File EGTS_protocol.cpp
 *
 * @brief Протокол ЕГТС для передачи истории
 *
 * Автор: Егоркин С.В.
 * Дата создания: 13.03.2014
 ***************************************************************************/
// Разрешение вывода текущей информации о ходе исполнения программы
#define LOCAL_DEBUG_LEVEL DEBUG_LEVEL_FULLDATA
#define DEBUG_MODULE_NAME "EGTS server: "

//#if defined(__EGTS_SERVER)

#include "background/guardConnect.hpp"
#include "background/taskbuffer.hpp"
#include "debug/debug.hpp"
#include "events/events.hpp"
#include "memory/event_memory.hpp"
#include "memory/history_rubber.hpp"
#include "memory/memory.hpp"
#include "utils/crypto_gost28147.hpp"
#include "protocols/modem/wifi.hpp"
#include "protocols/EGTS_protocol.hpp"
#include "time/sw_timer.hpp"
#include "utils/crypto.h"
#include "utils/local_string.hpp"
#include "general.h"
#include "local_types.hpp"

#pragma pack(push, 1)







ServerEGTSProtocol::ServerEGTSProtocol()
{
	IsConnectNeed = false;
	MaxRecordCount = BUFFERED_RECORDS_NUMBER;
#if defined(__USE_FULL_INIT_CONSTRUCTOR__)
	IsSendOk = false;
	RepeateCounter = 0;
	MaxRecordCount = 0;
	BufferedRecordCount = 0;
	memset(BufferedRecordIndex, 0, sizeof(BufferedRecordIndex));
	SendCache.fill({0, 0});

	State = TaskEGTSState_t::Idle;
//	SW_Timer TaskTimer;
//	SW_Timer ExchangeTimer;
	ForceHistoryStatus = ForceState::ForceSend;

	EGTSParams = {0};
	PID_Counter = 0;

	RxBuffer.fill(0);
	RxBufferLevel = 0;
	Find_start = false;
	CurFlagMask = 0;

	IsConnectNeed = false;
	NeverEndedTask = false;
	IsCloseNeed = false;

	RecordNumber = 0;

#if defined(__EGTS_STATISTIC__)
	UseStatistic = false;
	RtmBin2_SendCounter = 0;
	RtmBin2_DestinationUnit = EU_Empty;
	RtmBin2_DestinationAddress = 0;
#endif // defined(__EGTS_STATISTIC__)

#if defined(__EGTS_CRYPTO__)
	UseEncryption = false;
#endif // defined(__EGTS_CRYPTO__)
#if defined(__EGTS_EXTRA_AUTH__)
	UseExtendedAuthentication = false;

	CacheService = Service_t::AUTH_SERVICE;
	CacheSdrCount = 0;
	CachePacketId = 0;
#endif // defined(__EGTS_EXTRA_AUTH__)

#endif // defined(__USE_FULL_INIT_CONSTRUCTOR__)
}





/****************************************************************************
 * @name GetDestination
 * @brief Получить адрес сервера подключения для протокола
 *
 * @param Destination - указатель на буфер для чтения адреса
 * @param ChannelNumber - номер сервера (0 - основной, 1 - резервный)
 * @return true - адрес прочитан успешно
 ***************************************************************************/
bool ServerEGTSProtocol::GetDestination(TcpConnectDestination_t *Destination, uint8_t ChannelNumber)
{
	ServerConnectSettings_t ServerSettings;
	Memory.ConfigFile.ReadData(&ServerSettings, ConfigField::ServerConnectSettings, 2 + ChannelNumber);
	memcpy(Destination, &ServerSettings.ConnectionAddress, sizeof(*Destination));

	return true;
}




/****************************************************************************
 * @name IsDataReady
 * @brief Проверка доступности данных для отправки
 *
 * @param none
 * @return результат отправки данных. 0 - данных для отправки нет.
 ***************************************************************************/
bool ServerEGTSProtocol::IsDataReady()
{
	bool dataReady = false;

	uint16_t flagMask = Events::EventMemory.GetEGTSFlagMask();
	uint16_t supportedMask = AlarmTamperMask | AlarmExtVoltageMask | AlarmLoopInMask;
	if(flagMask & ~supportedMask)
	{
		Events::EventMemory.ClearFlagEGTS(~supportedMask);
		flagMask &= supportedMask;
	}

	if(flagMask != 0)
	{
		dataReady = true;
	}

	if(dataReady == false)
	{
		uint32_t currentRecordCount = History.GetDeltaIndexEGTS();
		if(currentRecordCount <= History.GetCurrentRecordLimit())
		{
			if(ForceHistoryStatus == ForceState::ForceSend)
			{
				DebugModuleTrace(DL_Trace, "History were sent completely\n");
				dataReady = true;
				if(currentRecordCount == 0)
				{
					ForceHistoryStatus = ForceState::ForceCreateHistoryBlock;
					if(!NeverEndedTask)
						IsConnectNeed = false;
				}
			}
			else
			{
				if(ExchangeTimer.IsExpired())
				{
					dataReady = true;
				}
			}
		}
		else
		{
			ForceHistoryStatus = ForceState::ForceSend;
			dataReady = true;
		}
	}


	return dataReady;
}


/**************************************************************************
 *
 *
 *
 *
 *
 **************************************************************************/

bool ServerEGTSProtocol::SendIdent()
{
	bool result = false;


#if defined __EGTS_AUTHENTIFICATION
	DebugModuleTrace(DL_Trace, "Send authentification in EGTS_SR_TERM_IDENTITY\n");
	DebugModuleTrace(DL_Trace, "Auth attempt %d\n", RepeateCounter);

	// Заполнение данных отправляемого пакета - сначала формирование записей
	TransportPacket_t *OutgoingPacketBuffer = (TransportPacket_t *) sprintbuf;
	// Заполнение данных отправляемых записей - сначала формирование подзаписей
	RecordSSLP *currentRecord = OutgoingPacketBuffer->Record;

	uint16_t RecordsDataSize = 0;

	if(FillResultCode::Normal == FillSubrecordIdentity(SPRINTBUF_SIZE, (void *)(currentRecord->Subrecord), RecordsDataSize))
	{
		HeaderSDR_t Header;
		Header.RL = RecordsDataSize;
		Header.RN = RecordNumber++;
		Header.RFL = 0x85;
		Header.OID = EGTSParams.Number;
		Header.TM = ConvertTime(0);
		Header.SST = Service_t::AUTH_SERVICE;
		Header.RST = Service_t::AUTH_SERVICE;

		memcpy(&currentRecord->Header, &Header, sizeof(Header));
		RecordsDataSize += sizeof(Header);

		CacheSdrCount = 1;
		CacheService = Service_t::AUTH_SERVICE;
		CachePacketId = PID_Counter;
		SendCache[0].RecordNumber = RecordNumber;
		SendCache[0].HistoryRecNum = RubberHistory::INDEX_NOT_EXIST;

		result = SendPacket(OutgoingPacketBuffer, Transport::PacketType::APPDATA, RecordsDataSize);
	}

#else
	DebugModuleTrace(DL_Data, "Not need authentification EGTS!\n");
	IsSendOk = true;
	return true;
#endif

	return result;
}


bool ServerEGTSProtocol::SendPacket(TransportPacket_t *OutgoingPacketBuffer, Transport::PacketType PacketType, uint16_t RecordsDataSize)
{
	// Формирование транспорта пакета
	uint16_t packetSize = TransportForming(OutgoingPacketBuffer, PacketType, RecordsDataSize);

	uint16_t sendDataCount = Send(OutgoingPacketBuffer, packetSize);

	if(sendDataCount != packetSize)
	{
		DebugModuleTrace(DL_Trace, "Error on sending! Not enought space in buffer!\n");
		return false;
	}

	DebugModuleTrace(DL_ExtendedData, "Packet №%d - send ok (%d bytes) :<", PID_Counter, packetSize);
	DebugTraceAscii(DL_FullData, OutgoingPacketBuffer, packetSize);
	DebugTrace(DL_ExtendedData, ">\n");

	PID_Counter++;
	return true;
}

/****************************************************************************
 * @name FillRecordCommonStatistic
 * @brief Формирование записи уровня поддержки услуг, содержащей подзаписи статистики передачи
 * данных на сервер ЕГТС
 *
 * @param	MaxDataSize - размер места в выходном буфере для формирования записи
 * 			RecordBuffer - указатель на выходной буфер записи
 * 			RecordSize - выходной размер записи
 * @return код результата выполнения из @FillResultCode
 ***************************************************************************/
FillResultCode ServerEGTSProtocol::FillRecordCommonStatistic(uint16_t MaxDataSize, RecordSSLP *RecordBuffer, uint16_t &RecordSize)
{
	DebugModuleTrace(DL_ExtendedData, "Fill common statistic values\n");

	// Подготовка буфера для формирования подзаписей
	TELEDATA_SERVICE_ABS_CNTR_DATA_Struct StatisticField[Constants::StatisticNumber];
	// Количество успешно заполненых подзаписей
	uint8_t usedFieldCount = 0;

	// Проверка на наличие места выходном буфере
	if(MaxDataSize < sizeof(StatisticField))
	{
		RecordSize = 0;
		return FillResultCode::BufferFull;
	}

	memset(&StatisticField, 0, sizeof(StatisticField));

	// Общая статистика
	StatisticField[usedFieldCount].Header.SRT = TELEDATA_SERVICE::SubrecordType::ABS_CNTR_DATA;
	StatisticField[usedFieldCount].Header.SRL = 4;
	StatisticField[usedFieldCount].CounterNumber = 100;
	memcpy(StatisticField[usedFieldCount].CounterValue, &Statistic.TotalConfirmed, 3);
	usedFieldCount++;

	StatisticField[usedFieldCount].Header.SRT = TELEDATA_SERVICE::SubrecordType::ABS_CNTR_DATA;
	StatisticField[usedFieldCount].Header.SRL = 4;
	StatisticField[usedFieldCount].CounterNumber = 101;
	memcpy(StatisticField[usedFieldCount].CounterValue, &Statistic.Unsent, 3);
	usedFieldCount++;

	StatisticField[usedFieldCount].Header.SRT = TELEDATA_SERVICE::SubrecordType::ABS_CNTR_DATA;
	StatisticField[usedFieldCount].Header.SRL = 4;
	StatisticField[usedFieldCount].CounterNumber = 102;
	memcpy(StatisticField[usedFieldCount].CounterValue, &Statistic.ConnectCounter, 3);
	usedFieldCount++;


	// Текущие индексы
	StatisticField[usedFieldCount].Header.SRT = TELEDATA_SERVICE::SubrecordType::ABS_CNTR_DATA;
	StatisticField[usedFieldCount].Header.SRL = 4;
	StatisticField[usedFieldCount].CounterNumber = 103;
	memcpy(StatisticField[usedFieldCount].CounterValue, &UniqueRecordID.New, 3);
	usedFieldCount++;

	StatisticField[usedFieldCount].Header.SRT = TELEDATA_SERVICE::SubrecordType::ABS_CNTR_DATA;
	StatisticField[usedFieldCount].Header.SRL = 4;
	StatisticField[usedFieldCount].CounterNumber = 104;
	memcpy(StatisticField[usedFieldCount].CounterValue, &UniqueRecordID.Old, 3);
	usedFieldCount++;


	// Время самой старой точки
	StatisticField[usedFieldCount].Header.SRT = TELEDATA_SERVICE::SubrecordType::ABS_CNTR_DATA;
	StatisticField[usedFieldCount].Header.SRL = 4;
	uint32_t recordTime = History.GetRecordTime(UniqueRecordID.Old);
	StatisticField[usedFieldCount].CounterNumber = 105;
	memcpy(StatisticField[usedFieldCount].CounterValue, &recordTime, 3);
	usedFieldCount++;

	StatisticField[usedFieldCount].Header.SRT = TELEDATA_SERVICE::SubrecordType::ABS_CNTR_DATA;
	StatisticField[usedFieldCount].Header.SRL = 4;
	StatisticField[usedFieldCount].CounterNumber = 106;
	memcpy(StatisticField[usedFieldCount].CounterValue, &recordTime, 3);
	usedFieldCount++;

	DebugTrace(DL_FullData, "Add old record time: Index %d, time 0x%08X\n", UniqueRecordID.Old, recordTime);


	RecordSize = usedFieldCount * sizeof(StatisticField[0]);
	memcpy(RecordBuffer->Subrecord, &StatisticField, RecordSize);

	HeaderSDR_t Header;
	Header.RL = RecordSize;
	Header.RN = RecordNumber++;
	Header.RFL = 0x85;
	Header.OID = EGTSParams.Number;
	Header.TM = ConvertTime(0);
	Header.SST = Service_t::TELEDATA_SERVICE;
	Header.RST = Service_t::TELEDATA_SERVICE;

	memcpy(&RecordBuffer->Header, &Header, sizeof(Header));

	RecordSize += sizeof(Header);

	DebugTrace(DL_SlowFullData, "Common statistic record: <");
//	DebugTraceAscii(DL_SlowFullData, (uint8_t *)RecordBuffer, RecordSize);
	DebugTrace(DL_SlowFullData, "\n");


	return FillResultCode::Normal;
}


/****************************************************************************
 * @name ConvertHistoryToPosData
 * @brief Конвертер записи истории в подзапись EGTS_SR_POS_DATA
 *
 * @param	HistoryRecord - указатель на область памяти, интерпретируемой как запись истории
 * 			MaxDataSize - размер места в выходном буфере для хранения подзаписи
 * 			OutputBuffer - указатель на выходной буфер подзаписи
 * 			SubrecordSize - выходной размер записи
 * @return	код выполнения операции @FillResultCode
 ***************************************************************************/
FillResultCode ServerEGTSProtocol::ConvertHistoryToPosData(const uint8_t *HistoryRecord, uint16_t MaxDataSize, void *OutputBuffer, uint16_t &SubrecordSize)
{
	DebugModuleTrace(DL_ExtendedData, "Fill EGTS_SR_POS_DATA subrecord\n");

	TELEDATA_SERVICE_POS_DATAStruct PosData;

	// Проверка на наличие места выходном буфере
	if(MaxDataSize < sizeof(PosData))
	{
		SubrecordSize = 0;
		return FillResultCode::BufferFull;
	}

	memset(&PosData, 0, sizeof(PosData));

	PosData.Header.SRT = TELEDATA_SERVICE::SubrecordType::POS_DATA;
	PosData.Header.SRL = sizeof(PosData) - sizeof(PosData.Header);

	uint8_t Date[3];
	uint8_t Time[3];
	History.GetDataFromRecordBuffer(HistoryRecord, RubberHistory::RecordId::DateBCD, Date);
	History.GetDataFromRecordBuffer(HistoryRecord, RubberHistory::RecordId::TimeBCD, Time);

	// NTM // время навигации (количество секунд с 00:00:00 01.01.2010 UTC)
	tm t;
	int tempYear = bcd2int(Date[0]);
	t.tm_year = (tempYear < 70 ) ? tempYear + 100 : tempYear;	// years since 1900
	t.tm_mon = ((Date[1] & 0xF0) >> 4) * 10 + (Date[1] & 0x0F) - 1;	// months since January: 0..11
	t.tm_mday = ((Date[2] & 0xF0) >> 4) * 10 + (Date[2] & 0x0F);	// day of the month: 1..31
	t.tm_sec = ((Time[0] & 0xF0) >> 4) * 10 + (Time[0] & 0x0F);		// seconds after the minute: 0..61
	t.tm_min = ((Time[1] & 0xF0) >> 4) * 10 + (Time[1] & 0x0F);		// minutes after the hour: 0..59
	t.tm_hour = ((Time[2] & 0xF0) >> 4) * 10 + (Time[2] & 0x0F);	// hours since midnight: 0..23
	PosData.NTM = ConvertTime(mktime(&t));

	// LAT // широта по модулю, градусы / 90 * 0xFFFFFFFF и взята целая часть
	uint32_t latitude; // Формат ddmm.mmmmmm. Координата из приемника *100000. Для южного полушария устанавливается старший бит в 1.
	History.GetDataFromRecordBuffer(HistoryRecord, RubberHistory::RecordId::Latitude, &latitude);
	if((latitude & 0x80000000) != 0)
		// FLG[5] LAHS полушарие широты: 0 - северная широта; 1 - южная широта
		PosData.FLG |= 0x20;
	latitude &= 0x7FFFFFFF;
	uint32_t grad = latitude / 10000000;
	uint32_t minutes = latitude % 10000000;
	latitude = grad * 10000000 + (double)minutes * 100.0 / 60.0;
	latitude = ((double)latitude / 10000000.0) / 90.0 * 0xFFFFFFFF;
	PosData.LAT = latitude;

	// LONG // долгота по модулю, градусы / 180 * 0xFFFFFFFF и взята целая часть
	uint32_t longitude; // Формат ddmm.mmmmmm. Координата из приемника *100000. Для южного полушария устанавливается старший бит в 1.
	History.GetDataFromRecordBuffer(HistoryRecord, RubberHistory::RecordId::Longitude, &longitude);
	if((longitude & 0x80000000) != 0)
		// FLG[6] LOHS полушарие долготы: 0 - восточная долгота; 1 - западная долгота
		PosData.FLG |= 0x40;
	longitude &= 0x7FFFFFFF;
	grad = longitude / 10000000;
	minutes = longitude % 10000000;
	longitude = grad * 10000000 + (double)minutes * 100.0 / 60.0;
	longitude = ((double)longitude / 10000000.0) / 180.0 * 0xFFFFFFFF;
	PosData.LONG = longitude;

	if(PosData.LAT != 0 && PosData.LONG != 0)
		// FLG[0] VLD признак «валидности» координатных данных: 1 - данные «валидны»; 0 - «невалидные» данные
		PosData.FLG |= 1;
	// FLG[3] BB признак отправки данных из памяти («чёрный ящик»): 0 - актуальные данные; 1 - данные из памяти («чёрного ящика»)
	PosData.FLG |= 0x08;

	bool MoveFlag;
	History.GetDataFromRecordBuffer(HistoryRecord, RubberHistory::RecordId::Bit_VoyagerCommon_MoveFlag, &MoveFlag);
	if(MoveFlag)
		PosData.FLG |= 0x10;

	// SPD[0:13] скорость в десятых долях км/ч (4 редакция протокола поддержки услуг)(используется 14 младших бит)
	uint32_t historySpeed;
	History.GetDataFromRecordBuffer(HistoryRecord, RubberHistory::RecordId::SpeedKnots, &historySpeed);
	//conversion 1 knot -> 0.01 km/h
	PosData.SPD = (uint16_t)((historySpeed * 1.852) / 100) & 0x3FFF;

	uint16_t historyDirection;
	History.GetDataFromRecordBuffer(HistoryRecord, RubberHistory::RecordId::Course, &historyDirection);
	PosData.DIR = (uint8_t)(historyDirection & 0x00FF);
	// SPD[15] DIRH (Direction the Highest bit) старший бит параметра DIR
	if((historyDirection & 0x100) != 0)
		PosData.SPD = (PosData.SPD | 0x8000);

#if defined(__NAV_COUNTER_SUPPORT__)
	uint32_t historyMileage;
	History.GetDataFromRecordBuffer(HistoryRecord, RubberHistory::RecordId::NavMileage, &historyMileage);
	historyMileage /= 100;//переводим из 1м в 0,1км
	memcpy(PosData.ODM, &historyMileage, sizeof(PosData.ODM));
#endif
	bool currentBitValue;
	History.GetDataFromRecordBuffer(HistoryRecord, RubberHistory::RecordId::Bit_DiscreteInput1, &currentBitValue);
	if(currentBitValue)
		PosData.DIN |= 1;
	History.GetDataFromRecordBuffer(HistoryRecord, RubberHistory::RecordId::Bit_DiscreteInput2, &currentBitValue);
	if(currentBitValue)
		PosData.DIN |= 2;
	History.GetDataFromRecordBuffer(HistoryRecord, RubberHistory::RecordId::Bit_DiscreteInput3, &currentBitValue);
	if(currentBitValue)
		PosData.DIN |= 4;
	History.GetDataFromRecordBuffer(HistoryRecord, RubberHistory::RecordId::Bit_DiscreteInput4, &currentBitValue);
	if(currentBitValue)
		PosData.DIN |= 8;

	PosData.SRC = 1;

	DebugModuleTrace(DL_ExtendedData, "Fill EGTS_SR_POS_DATA");
	DebugTrace(DL_ExtendedData, " (%d bytes) :<", sizeof(PosData));
//	DebugTraceAscii(DL_ExtendedData, &PosData, sizeof(PosData));
	DebugTrace(DL_ExtendedData, ">");
	DebugTrace(DL_ExtendedData, "\n");


	memcpy(OutputBuffer, &PosData, sizeof(PosData));

	SubrecordSize = sizeof(PosData);
	return FillResultCode::Normal;
}


/****************************************************************************
 * @name ConvertHistoryToExtPosData
 * @brief Конвертер записи истории в подзапись EGTS_SR_EXT_POS_DATA
 *
 * @param	HistoryRecord - указатель на область памяти, интерпретируемой как запись истории
 * 			MaxDataSize - размер места в выходном буфере для хранения подзаписи
 * 			OutputBuffer - указатель на выходной буфер подзаписи
 * 			SubrecordSize - выходной размер записи
 * @return	код выполнения операции @FillResultCode
 ***************************************************************************/
FillResultCode ServerEGTSProtocol::ConvertHistoryToExtPosData(const uint8_t *HistoryRecord, uint16_t MaxDataSize, void *OutputBuffer, uint16_t &SubrecordSize)
{
	DebugModuleTrace(DL_ExtendedData, "Fill EGTS_SR_EXT_POS_DATA subrecord\n");
	TELEDATA_SERVICE_EXT_POS_DATAStruct ExtPosData;

	// Проверка на наличие места выходном буфере
	if(MaxDataSize < sizeof(ExtPosData))
	{
		SubrecordSize = 0;
		return FillResultCode::BufferFull;
	}

	memset(&ExtPosData, 0, sizeof(ExtPosData));


	ExtPosData.Header.SRT = TELEDATA_SERVICE::SubrecordType::EXT_POS_DATA;
	ExtPosData.Header.SRL = sizeof(ExtPosData) - sizeof(ExtPosData.Header);

	ExtPosData.Flags = 0x1F; // Передаются все поля
	History.GetDataFromRecordBuffer(HistoryRecord, RubberHistory::RecordId::VDOP, &ExtPosData.VDOP);
	History.GetDataFromRecordBuffer(HistoryRecord, RubberHistory::RecordId::HDOP, &ExtPosData.HDOP);
	History.GetDataFromRecordBuffer(HistoryRecord, RubberHistory::RecordId::PDOP, &ExtPosData.PDOP);
	History.GetDataFromRecordBuffer(HistoryRecord, RubberHistory::RecordId::SattelitesNum, &ExtPosData.SAT);
	ExtPosData.NS = 0x0003;	// ГЛОНАСС + GPS

	uint8_t *debugData = (uint8_t *)&ExtPosData;
	for(uint16_t count = 0; count < sizeof(ExtPosData); count++)
	{
		DebugTrace(DL_FullData, "0x%02X ", *(debugData++) );
		if((count % 16) == 15)
		{
			DebugTrace(DL_FullData, "\n");
		}
	}
	DebugTrace(DL_FullData, "\n");

	memcpy(OutputBuffer, &ExtPosData, sizeof(ExtPosData));

	SubrecordSize = sizeof(ExtPosData);
	return FillResultCode::Normal;
}


/****************************************************************************
 * @name ConvertHistoryToLiquidSensor
 * @brief Конвертер записи истории в подзапись EGTS_SR_LIQUID_LEVEL_SENSOR
 *
 * @param	HistoryRecord - указатель на область памяти, интерпретируемой как запись истории
 * 			MaxDataSize - размер места в выходном буфере для хранения подзаписи
 * 			OutputBuffer - указатель на выходной буфер подзаписи
 * 			SubrecordSize - выходной размер записи
 * @return 	код выполнения операции @FillResultCode
 ***************************************************************************/
FillResultCode ServerEGTSProtocol::ConvertHistoryToLiquidSensor(const uint8_t *HistoryRecord, uint16_t MaxDataSize, void *OutputBuffer, uint16_t &SubrecordSize)
{
	DebugModuleTrace(DL_ExtendedData, "Fill EGTS_SR_LIQUID_LEVEL_SENSOR subrecords\n");
	uint8_t *currentOutputData = (uint8_t *)OutputBuffer;

	uint32_t dataSize = 0;

	// Перебор всех возможных датчиков топлива
	for(uint8_t sensorCount = 0; sensorCount < (sizeof(LiquidSendorDescriptor) / sizeof(LiquidSendorDescriptor[0])) ; sensorCount++)
	{
		TELEDATA_SERVICE_LIQUID_LEVEL_SENSORStruct liquidSensorSubrecord;

		// Проверка наличия места в буфере
		if(MaxDataSize < (dataSize + sizeof(liquidSensorSubrecord)) )
		{
			// места не достаточно - выход с установкой размера как у переполненного буфера
			SubrecordSize = 0;
			return FillResultCode::BufferFull;
		}

		DebugModuleTrace(DL_ExtendedData, "Add liquid_sensor %d\n", sensorCount);
		uint32_t sensorData = 0;
		if(!History.GetDataFromRecordBuffer(HistoryRecord, LiquidSendorDescriptor[sensorCount].DataType, &sensorData))
		{
			DebugModuleTrace(DL_ExtendedData, "Data unavailable\n");
			continue;
		}

		if(LiquidSendorDescriptor[sensorCount].DataType == RubberHistory::RecordId::CAN_fuel_l)
		{
			// Проверка на отсутствие данных в шине
			if(sensorData & 0x8000)
			{
				DebugModuleTrace(DL_ExtendedData, "Data masked as absent\n");
				continue;
			}

			// Приведение к протокольным ед.изм. ( *0,1л) из ед.изм. истории ( *1л)
			sensorData *= 10;
		}
		if(LiquidSendorDescriptor[sensorCount].DataType == RubberHistory::RecordId::CAN_fuel_p)
		{
			// Проверка на отсутствие данных в шине
			if(sensorData & 0x80)
			{
				DebugModuleTrace(DL_ExtendedData, "Data masked as absent\n");
				continue;
			}
		}

		liquidSensorSubrecord.Header.SRT = TELEDATA_SERVICE::SubrecordType::LIQUID_LEVEL_SENSOR;
		liquidSensorSubrecord.Header.SRL = sizeof(liquidSensorSubrecord) - sizeof(liquidSensorSubrecord.Header);
		liquidSensorSubrecord.Flags = (uint8_t) (LiquidSendorDescriptor[sensorCount].Flags);
		liquidSensorSubrecord.MADDR = LiquidSendorDescriptor[sensorCount].Address;
		liquidSensorSubrecord.LLSD = sensorData;

		uint8_t *debugData = (uint8_t *)&liquidSensorSubrecord;
		for(uint16_t count = 0; count < sizeof(liquidSensorSubrecord); count++)
		{
			DebugTrace(DL_SlowFullData, "0x%02X ", *(debugData++) );
			if((count % 16) == 15)
			{
				DebugTrace(DL_SlowFullData, "\n");
			}
		}
		DebugTrace(DL_SlowFullData, "\n");

		memcpy(currentOutputData, &liquidSensorSubrecord, sizeof(liquidSensorSubrecord));
		currentOutputData += sizeof(liquidSensorSubrecord);
		dataSize += sizeof(liquidSensorSubrecord);
	}

	SubrecordSize = dataSize;
	return FillResultCode::Normal;
}



/****************************************************************************
 * @name ConvertTime
 * @brief Конвертер времени POSIX в формат ЕГТС (начиная с 01.01.2010 UTC)
 *
 * @param	time - исходное время для конвертации, 0 для получения текущего времени
 * @return	секунд с 01.01.2010 UTC
 ***************************************************************************/
clock_t ServerEGTSProtocol::ConvertTime(clock_t time)
{
	clock_t egtsTime = 0;

	if(time == 0)
	{
		time = STime.GetRealTime();
	}

	if(time < Constants::BaseTimeStamp)
		egtsTime = 0;
	else
		egtsTime = time - Constants::BaseTimeStamp;

	return egtsTime;
}


/****************************************************************************
 * @name FillRecordFromHistory
 * @brief Конвертер записи истории в запись сервиса TELEDATA (набор подзаписей)
 *
 * @param	RecordIndex - Индекс записи истории для конвертации
 * 			MaxDataSize - размер места в выходном буфере для хранения подзаписи
 * 			OutputBuffer - указатель на выходной буфер подзаписи
 * 			SubrecordSize - выходной размер записи
 * @return	Результат работы функции @ref FillResultCode
 ***************************************************************************/
FillResultCode ServerEGTSProtocol::FillRecordFromHistory(uint32_t RecordIndex, uint16_t MaxDataSize, RecordSSLP *RecordBuffer, uint16_t &RecordSize)
{
	uint8_t *recordBuffer = (uint8_t *)sprintbuf1;
	SubrecordSSLP *currentSubRecord = RecordBuffer->Subrecord;

	RecordSize = 0;

	if(History.ReadRecord(RecordIndex, recordBuffer, SPRINTBUF1_SIZE) == 0)
		return FillResultCode::WrongRecord;

	DebugModuleTrace(DL_ExtendedData, "Record %d - read ok\n", RecordIndex);

#if defined(__EGTS_STATISTIC__)
	if(UseStatistic)
	{
		// Подготовка буфера для формирования подзаписей
		TELEDATA_SERVICE_ABS_CNTR_DATA_Struct StatisticField[2];
		// Количество успешно заполенных подзаписей
		uint8_t usedFieldCount = 0;

		// Текущие индексы
		uint32_t counterValue = RecordIndex & 0x00FFFFFF;
		StatisticField[usedFieldCount].Header.SRT = TELEDATA_SERVICE::SubrecordType::ABS_CNTR_DATA;
		StatisticField[usedFieldCount].Header.SRL = 4;
		StatisticField[usedFieldCount].CounterNumber = 110;
		memcpy(StatisticField[usedFieldCount].CounterValue, &counterValue, 3);
		usedFieldCount++;

		counterValue = (RecordIndex >> 24) & 0x000000FF;
		StatisticField[usedFieldCount].Header.SRT = TELEDATA_SERVICE::SubrecordType::ABS_CNTR_DATA;
		StatisticField[usedFieldCount].Header.SRL = 4;
		StatisticField[usedFieldCount].CounterNumber = 111;
		memcpy(StatisticField[usedFieldCount].CounterValue, &counterValue, 3);
		usedFieldCount++;

		RecordSize = sizeof(StatisticField);
		memcpy(currentSubRecord, StatisticField, RecordSize);

		DebugModuleTrace(DL_FullData, "Current record stat: <");
		DebugTraceAscii(DL_FullData, StatisticField, RecordSize);
		DebugTrace(DL_FullData, ">\n");

		MaxDataSize -= RecordSize;
		currentSubRecord = (SubrecordSSLP *)((uint8_t *)currentSubRecord + RecordSize);
	}
#endif // defined(__EGTS_STATISTIC__)


	// заполняется подзапись EGTS_SR_POS_DATA
	uint16_t posDataSize = 0;
	if(ConvertHistoryToPosData(recordBuffer, MaxDataSize, currentSubRecord, posDataSize) != FillResultCode::Normal)
		return FillResultCode::BufferFull;

	MaxDataSize -= posDataSize;
	RecordSize += posDataSize;
	currentSubRecord = (SubrecordSSLP *)((uint8_t *)currentSubRecord + posDataSize);

	// заполняется подзапись EGTS_SR_EXT_POS_DATA
	uint16_t extPosDataSize = 0;
	if(ConvertHistoryToExtPosData(recordBuffer, MaxDataSize, currentSubRecord, extPosDataSize) != FillResultCode::Normal)
		return FillResultCode::BufferFull;

	MaxDataSize -= extPosDataSize;
	RecordSize += extPosDataSize;
	currentSubRecord = (SubrecordSSLP *)((uint8_t *)currentSubRecord + extPosDataSize);

	// заполняется подзапись EGTS_SR_LIQUID_LEVEL_SENSOR
	uint16_t sensorsDataSize = 0;
	if(ConvertHistoryToLiquidSensor(recordBuffer, MaxDataSize, currentSubRecord, sensorsDataSize) != FillResultCode::Normal)
		return FillResultCode::BufferFull;

	MaxDataSize -= sensorsDataSize;
	RecordSize += sensorsDataSize;
	currentSubRecord = (SubrecordSSLP *)((uint8_t *)currentSubRecord + sensorsDataSize);

	HeaderSDR_t Header;
	Header.RL = RecordSize;
	Header.RN = RecordNumber++;
	Header.RFL = 0x85;
	Header.OID = EGTSParams.Number;
	Header.TM = ConvertTime(0);
	Header.SST = Service_t::TELEDATA_SERVICE;
	Header.RST = Service_t::TELEDATA_SERVICE;

	memcpy(&RecordBuffer->Header, &Header, sizeof(Header));

	RecordSize += sizeof(Header);

	return FillResultCode::Normal;
}


/**************************************************************************
 * @name SendHistory
 * @brief Отправка истории прибора на сервер ЕГТС  в формате посылок EGTS_SR_POS_DATA
 *
 * @param
 * @return
 *************************************************************************/
bool ServerEGTSProtocol::SendHistory()
{
	bool result = false;

	size_t assumedBufferSize = ExchangePort->GetVolume();
	if(assumedBufferSize > 1110)
		assumedBufferSize = 1110;

	// Проверка доступного места в буфере на вместимость хотя бы одной записи пакета сервиса
	size_t packetOverheadSize = sizeof(HeaderTransport_t) + sizeof(HeaderSDR_t) + 2;
	if(assumedBufferSize <= packetOverheadSize)
		return result;

	assumedBufferSize -= packetOverheadSize;

	// Чтение доступных записей из флэш в область данных буфера для передачи
	// Заполнение данных отправляемого пакета - сначала формирование записей
	TransportPacket_t *OutgoingPacketBuffer = (TransportPacket_t *) sprintbuf;
	// Заполнение данных отправляемых записей - сначала формирование подзаписей
	RecordSSLP *currentRecord = OutgoingPacketBuffer->Record;

	//! Размер сформированного набора записей пакета
	uint16_t ServiceDataRecordSize = 0;
	CacheSdrCount = 0;

	uint16_t recordSize = 0;
	FillResultCode fillResult = FillResultCode::Normal;

	if(UseStatistic)
	{
		SendCache[CacheSdrCount].RecordNumber = RecordNumber;
		fillResult = FillRecordCommonStatistic(assumedBufferSize, currentRecord, recordSize);
		if(fillResult == FillResultCode::Normal)
		{
			CacheSdrCount++;

			// Подзаписи успешно добавлены в буфер
			currentRecord = (RecordSSLP *)((uint8_t *)currentRecord + recordSize);
			assumedBufferSize -= recordSize;
			ServiceDataRecordSize += recordSize;
		}
		else
		{
			DebugModuleTrace(DL_Trace, "Unexpected statistic error!\n");
			return result;
		}
	}


	BufferedRecordCount = 0;
	uint32_t assumedRecordIndex = History.FindIndexFirstUnsentRecordEGTS();
	// Максимальный на текущий момент индекс записи
	uint32_t maxRecordIndex = assumedRecordIndex + History.GetDeltaIndexEGTS();
	DebugModuleTrace(DL_Trace, "Estimated start index - %d (max %d)\n", assumedRecordIndex, maxRecordIndex);

	while(BufferedRecordCount < MaxRecordCount)
	{
		if(assumedRecordIndex >= maxRecordIndex)
		{
			DebugModuleTrace(DL_Trace, "History completely sent\n");
			break;
		}

		SendCache[CacheSdrCount].RecordNumber = RecordNumber;
		SendCache[CacheSdrCount].HistoryRecNum = assumedRecordIndex;
		recordSize = 0;
		fillResult = FillRecordFromHistory(assumedRecordIndex, assumedBufferSize, currentRecord, recordSize);
		if(fillResult == FillResultCode::WrongRecord)
		{
			DebugModuleTrace(DL_Data, "Record %d unavailable, skip\n", assumedRecordIndex);
			History.MarkRecordSendedEGTS(assumedRecordIndex);
			assumedRecordIndex++;
			continue;
		}
		else
		{
			if(fillResult == FillResultCode::BufferFull)
			{
				DebugModuleTrace(DL_Data, "Data doesn`t fit in buffer, stop at record %d\n", assumedRecordIndex);
				break;
			}
		}

		// Подзаписи успешно добавлены в буфер
		currentRecord = (RecordSSLP *)((uint8_t *)currentRecord + recordSize);
		assumedBufferSize -= recordSize;
		ServiceDataRecordSize += recordSize;
		CacheSdrCount++;

		// Все подзаписи одной записи истории поместились - можно отправлять.
		BufferedRecordIndex[BufferedRecordCount] = assumedRecordIndex;
		BufferedRecordCount++;
		assumedRecordIndex++;
	}

	// Если есть прочитанные записи
	if(BufferedRecordCount >= MINIMAL_RECORD_SEND)
	{
		result = true;

		_LocalTraceDelimiter(DL_Data);
		DebugModuleTrace(DL_Data, "Send %d records to server (%u - %u)\n", BufferedRecordCount, SendCache[0].HistoryRecNum, SendCache[BufferedRecordCount - 1].HistoryRecNum);

		CacheService = Service_t::TELEDATA_SERVICE;
		CachePacketId = PID_Counter;

		if(false == SendPacket(OutgoingPacketBuffer, Transport::PacketType::APPDATA, ServiceDataRecordSize))
		{
			result = false;
			if(MaxRecordCount <= 1)
			{
				DebugModuleTrace(DL_ExtendedData, "Error on history sending!\n");
				Reset();
			}
			else
				MaxRecordCount /= 2;
		}
	}
	return result;
}


/****************************************************************************
 * @name SendMFlag
 * @brief Формирование и отправка тревог на сервер
 *
 * @param none
 * @return true - отправка успешна
 ***************************************************************************/
bool ServerEGTSProtocol::SendMFlag()
{
	bool result = false;

	uint16_t executedFlags = Events::EventMemory.GetEGTSFlagMask();
	DebugModuleTrace(DL_Data, "Current flags mask: 0x%04X\n", executedFlags);
	// Заполнение данных отправляемого пакета - сначала формирование записей
	TransportPacket_t *OutgoingPacketBuffer = (TransportPacket_t *) sprintbuf;
	// Заполнение данных отправляемых записей - сначала формирование подзаписей
	RecordSSLP *currentRecord = OutgoingPacketBuffer->Record;
	//! Размер сформированного набора записей пакета
	uint16_t ServiceDataRecordSize = 0;

	size_t assumedBufferSize = ExchangePort->GetVolume();
	if(assumedBufferSize > SPRINTBUF_SIZE)
		assumedBufferSize = SPRINTBUF_SIZE;

	size_t packetOverheadSize = sizeof(HeaderTransport_t) + sizeof(HeaderSDR_t) + 2;
	if(assumedBufferSize <= packetOverheadSize)
		return result;

	assumedBufferSize -= packetOverheadSize;

	for(uint16_t flagCount = 0; flagCount < 16; flagCount++)
	{
		uint16_t currentFlagMask = executedFlags & (1 << flagCount);
		if(currentFlagMask)
		{
			bool recordHasIncorrectTime = false;
			clock_t flagTime = Events::EventMemory.GetMFlagTime(flagCount);

			DebugModuleTrace(DL_Data, "Flag 0x%04X, time %d\n", currentFlagMask, flagTime);

			uint8_t *recordBuffer = (uint8_t *)sprintbuf1;
			if(flagTime > Constants::BaseTimeStamp)
			{
				uint32_t foundedIndex = History.FindRecordByTime(flagTime);
				DebugModuleTrace(DL_Data, "Record %d\n", foundedIndex);

				if(foundedIndex == RubberHistory::IndexValues::INDEX_NOT_EXIST)
					recordHasIncorrectTime = true;
			}
			else
				recordHasIncorrectTime = true;


			if(recordHasIncorrectTime)
				memset(recordBuffer, 0, History.ReadRecordSize());

			SubrecordSSLP *currentSubrecord = currentRecord->Subrecord;

			// заполняется подзапись EGTS_SR_POS_DATA
			uint16_t posDataSize = 0;
			if(ConvertHistoryToPosData(recordBuffer, assumedBufferSize, currentSubrecord, posDataSize) != FillResultCode::Normal)
				break;

			// Возможно требуется корректировка полей NTM и SRC
			TELEDATA_SERVICE_POS_DATAStruct *correctPosData = (TELEDATA_SERVICE_POS_DATAStruct *)currentSubrecord;
			if(recordHasIncorrectTime)
				correctPosData->NTM = ConvertTime(flagTime);

			correctPosData->SRC = 0;
			if(currentFlagMask & AlarmTamperMask)
				correctPosData->SRC = 10;
			if(currentFlagMask & AlarmExtVoltageMask)
				correctPosData->SRC = 11;
			if(currentFlagMask & AlarmLoopInMask)
				correctPosData->SRC = 13;

			if(correctPosData->SRC == 0)
			{
				DebugModuleTrace(DL_Data, "wrong source, skip record\n");
				continue;
			}

			DebugModuleTrace(DL_Data, "POS_DATA ok, src %d\n", correctPosData->SRC);

			assumedBufferSize -= posDataSize;
			currentSubrecord = (SubrecordSSLP *)((uint8_t *)currentSubrecord + posDataSize);
			ServiceDataRecordSize += posDataSize;
			uint16_t RecordSize = posDataSize;

			CurFlagMask |= currentFlagMask;

#if defined __ALARM_EGTS_POS_LOOPIN_DATA			// Проверка на необходимость добавления информации о шлейфах - только для тревожных кнопок
			if(currentFlagMask & AlarmLoopInMask)
			{
				uint16_t loopinDataSize = 0;

				if(FillSubrecordLoopin(currentFlagMask & AlarmLoopInMask, assumedBufferSize, currentSubrecord, loopinDataSize) != FillResultCode::Normal)
					continue;

				DebugModuleTrace(DL_Data, "Add LOOPIN_DATA\n");
				assumedBufferSize -= loopinDataSize;
				currentSubrecord = (SubrecordSSLP *)((uint8_t *)currentSubrecord + loopinDataSize);
				ServiceDataRecordSize += loopinDataSize;
				RecordSize += loopinDataSize;
			}
#endif // defined __ALARM_EGTS_POS_LOOPIN_DATA



			SendCache[0].RecordNumber = RecordNumber;
			SendCache[0].HistoryRecNum = RubberHistory::INDEX_NOT_EXIST;
			CacheSdrCount = 1;

			HeaderSDR_t Header;
			Header.RL = RecordSize;
			Header.RN = RecordNumber++;
			Header.RFL = 0x85;
			Header.OID = EGTSParams.Number;
			Header.TM = ConvertTime(0);
			Header.SST = Service_t::TELEDATA_SERVICE;
			Header.RST = Service_t::TELEDATA_SERVICE;

			memcpy(&currentRecord->Header, &Header, sizeof(Header));

			ServiceDataRecordSize += sizeof(Header);
			currentRecord = (RecordSSLP *)((uint8_t *)currentRecord + RecordSize + sizeof(Header));
		}
	}

	if(ServiceDataRecordSize != 0)
	{
		CacheService = Service_t::TELEDATA_SERVICE;
		CachePacketId = PID_Counter;

		if(SendPacket(OutgoingPacketBuffer, Transport::PacketType::APPDATA, ServiceDataRecordSize))
		{
			result = true;
		}
		else
		{
			CurFlagMask = 0xFFFF;
			IsSendOk = true;
		}
	}

	return result;
}


/****************************************************************************
 * @name	FillSubrecordLoopin
 * @brief	Формирование подзаписи авторизации TERM_IDENTITY
 *
 * @param	SubrecordFlagMask - битовая маска флагов тревог (из MFLAG)
 * 			MaxDataSize - максимальный размер подзаписи
 * 			OutputBuffer - указатель на буфер для формирования записи
 * 			SubrecordSize - размер сформированной подзаписи
 * @return	код выполнения операции @FillResultCode
 ***************************************************************************/
FillResultCode ServerEGTSProtocol::FillSubrecordLoopin (uint16_t AlarmFlagMask, uint16_t MaxDataSize, void *OutputBuffer, uint16_t &SubrecordSize)
{
	if(!CurFlagMask)
		return FillResultCode::WrongRecord;

	TELEDATA_SERVICE_LOOPIN_DATAStruct LOOPIN_DATA;

	if(MaxDataSize < sizeof(LOOPIN_DATA))
		return FillResultCode::BufferFull;

	SubrecordSize = 0;
	memset(&LOOPIN_DATA, 0, sizeof(LOOPIN_DATA));

	uint8_t count_alarms = 0; 	//common counts of events (on and off) for count number of LIS-es
	uint8_t loop_mask = 1;		//bit-mask of current loop
	for(uint_fast8_t count = 0; count < 16; count++) //see for all flags
	{
		if(AlarmFlagMask & (1 << count))
		{
			loop_mask <<= (count >> 1);
			LOOPIN_DATA.LIFE |= loop_mask;

			//One LIS is using for 2 loops
			if(!(count % 2)) //count is even - loop on
				LOOPIN_DATA.LIS[count_alarms >> 1] |= (uint8_t)(1 << (4 * (count_alarms % 2)));
			else //count is odd - loop off
				LOOPIN_DATA.LIS[count_alarms >> 1] &= (uint8_t)(0xF0 >> (4 * (count_alarms % 2)));;

			count_alarms++;

		}
	}

	if(count_alarms)
	{
		uint8_t size_loopin_data = 1 + ((count_alarms + 1) >> 1); //LIFE + LIS;

		LOOPIN_DATA.Header.SRT = TELEDATA_SERVICE::SubrecordType::LOOPIN_DATA;
		LOOPIN_DATA.Header.SRL = size_loopin_data;

		SubrecordSize = sizeof(LOOPIN_DATA.Header) + size_loopin_data;

		memcpy(OutputBuffer, &LOOPIN_DATA, SubrecordSize);
	}

	return FillResultCode::Normal;
}


/****************************************************************************
 * @name	FillSubrecordIdentity
 * @brief	Формирование подзаписи авторизации TERM_IDENTITY
 *
 * @param	MaxDataSize - максимальный размер подзаписи
 * 			OutputBuffer - указатель на буфер для формирования записи
 * 			SubrecordSize - размер сформированной подзаписи
 * @return	код выполнения операции @FillResultCode
 ***************************************************************************/
FillResultCode ServerEGTSProtocol::FillSubrecordIdentity(uint16_t MaxDataSize, void *OutputBuffer, uint16_t &SubrecordSize)
{
	AUTH_SERVICE_TERM_IDENTITYStruct TERM_IDENTITY;

	if(MaxDataSize <sizeof(TERM_IDENTITY))
		return FillResultCode::BufferFull;

	SubrecordSize = 0;
	memset(&TERM_IDENTITY, 0, sizeof(TERM_IDENTITY));

	TERM_IDENTITY.Header.SRT = AUTH_SERVICE::SubrecordType::EGTS_SR_TERM_IDENTITY;
	TERM_IDENTITY.Header.SRL = sizeof(TERM_IDENTITY) - sizeof(TERM_IDENTITY.Header);


	TERM_IDENTITY.TID = EGTSParams.Number;
	DebugModuleTrace(DL_Data, "Terminal Identifier - %d\n", TERM_IDENTITY.TID);

	TERM_IDENTITY.FLG = 0x03; // HDIDE=1 IMEIE=1
	DebugModuleTrace(DL_Data, "Flags - 0x%02X\n", TERM_IDENTITY.FLG);

	Memory.ConfigFile.ReadData(&TERM_IDENTITY.HDID, ConfigField::EGTS_DispatcherID);
	DebugModuleTrace(DL_Data, "Home Dispatcher Identifier - %d\n", TERM_IDENTITY.HDID);

	Imei_t Imei = Device::ReadIMEI();
	if(Imei.IsValid)
	{
		strcpy(TERM_IDENTITY.IMEI, Imei.Data.String);
	}
	else
		memset(TERM_IDENTITY.IMEI, '0', sizeof(TERM_IDENTITY.IMEI));

	DebugModuleTrace(DL_Data, "IMEI - %s\n", TERM_IDENTITY.IMEI);

	memcpy(OutputBuffer, &TERM_IDENTITY, sizeof(TERM_IDENTITY));
	SubrecordSize = sizeof(TERM_IDENTITY);

	return FillResultCode::Normal;
}


/****************************************************************************
 * @name TransportForming
 * @brief Формирование заголовка транспортного уровня
 * Данные для отправки находятся в буфере по адресу OutgoingPacketBuffer и учитывают
 * смещение данных от начала пакета
 *
 * @param OutgoingPacketBuffer - буфер для формирования пакета. В него заранее помещены данные.
 * @param PacketType - тип пакета Транспортного уровня. This parameter can be a value of @ref TransportPacketType
 * @param SDR_size - размер сформированных записей SDR[n]
 *
 * @return размер сформированного пакета
 ***************************************************************************/
uint16_t ServerEGTSProtocol::TransportForming(TransportPacket_t *OutgoingPacketBuffer,
											Transport::PacketType PacketType,
											uint16_t SDR_size
											)
{
#if defined(__EGTS_CRYPTO__)
	// Ecnryption - решение о применении шифрования принимается после авторизации и получения EGTS_SR_AUTH_PARAM
	if(UseEncryption)
	{
		ExtendTime_t perfEncryption = *STime.GetFullTime();
		// Количество байт для шифрования должно быть кратно 8
		uint16_t encryptedDataSize = (SDR_size + 7) & ~0x0007;

		if(encryptedDataSize != SDR_size)
			memset((uint8_t *)OutgoingPacketBuffer->Record + SDR_size, 0, encryptedDataSize - SDR_size);

		SDR_size = Gost28147::Encrypt(OutgoingPacketBuffer->Record, encryptedDataSize);

		ExtendTime_t deltaEncryption = *STime.GetFullTime();

		deltaEncryption = deltaEncryption - perfEncryption;
		DebugModuleTrace(DL_Data, "Encryption duration: %d.%03d\n", deltaEncryption.Second, deltaEncryption.Millisecond);
	}
#endif // defined(__EGTS_CRYPTO__)

	// TRANSPORT HEADER
	OutgoingPacketBuffer->Header.PRV = Constants::ProtocolVersion;
	OutgoingPacketBuffer->Header.SKID = 0;
#if defined(__EGTS_CRYPTO__)
	if(UseEncryption)
		OutgoingPacketBuffer->Header.Mask_1 = 1 << 3;		// ENA = 1
	else
		OutgoingPacketBuffer->Header.Mask_1 = 0;
#else
	OutgoingPacketBuffer->Header.Mask_1 = 0;
#endif // defined(__EGTS_CRYPTO__)

	OutgoingPacketBuffer->Header.HL = sizeof(OutgoingPacketBuffer->Header);
	OutgoingPacketBuffer->Header.HE = 0;
	OutgoingPacketBuffer->Header.FDL = SDR_size;
	OutgoingPacketBuffer->Header.PID = PID_Counter;
	OutgoingPacketBuffer->Header.PT = PacketType;
	OutgoingPacketBuffer->Header.HCS = CalcCRC8_31((uint8_t *)OutgoingPacketBuffer, sizeof(OutgoingPacketBuffer->Header) - 1);


	//Data(set early)


	// SFRCS
	uint16_t crcValue = Crc16((uint8_t *)(&OutgoingPacketBuffer->Record[0]), SDR_size);
	uint8_t * crcPtr = (uint8_t *)(&OutgoingPacketBuffer->Record[0]) + SDR_size;
	memcpy(crcPtr, (uint8_t*)&crcValue, 2);

	uint16_t packetSize = sizeof(OutgoingPacketBuffer->Header) + SDR_size + 2;

	return packetSize;
}




bool ServerEGTSProtocol::Binding(SerialChannel_c * PairPort)
{
	if(this->SerialChannel_c::Binding(PairPort))
	{
		if(TiedPort != NULL)
		{
			DebugModuleTrace(DL_Trace, "Binding ExchangePort!\n");
			ExchangePort = (TcpChannel_C *)TiedPort;
			return true;
		}
	}
	else
		Reset();
	return false;
}



/****************************************************************************
 * @name
 * @brief Проверка сообщений
 * Получение входящих сообщений текущей задачей.
 * Обрабатываются сообщения запуска/остановки задачи.
 *
 * @param
 * @return none
 ***************************************************************************/
void ServerEGTSProtocol::CheckMessage()
{
	UnitActivationTask TaskData;
	Task_t serverConnectTask(EU_ServerEgts, Task_t::ServerStartConnect,	sizeof(TaskData));

	bool isTaskStarted = false;
	bool isTaskStopped = false;
	bool isNeverEndedTask = false;

	TaskBuffer.GetTask(&serverConnectTask, &TaskData);

	if(serverConnectTask.Size != 0)
	{
		isTaskStarted = false;
		isTaskStopped = false;
		isNeverEndedTask = false;

		DebugModuleTrace(DL_ExtendedData, "Received message, current state - %d\n", State);
		switch (TaskData.Action)
		{
			case Task_t::StartAction:
			{
				switch (TaskData.Execute)
				{
					case ExecuteType_Always:
					{
						if(!NeverEndedTask)
						{
							DebugModuleTrace(DL_Trace, "Start always execute\n");
							isTaskStarted = true;
							isNeverEndedTask = true;
						}
						break;
					}
					case ExecuteType_Once:
					{
						DebugModuleTrace(DL_Trace, "Start single execute\n");
						isTaskStarted = true;
						break;
					}
					case ExecuteType_AlwaysStop_OnceStart:
					{
						DebugModuleTrace(DL_Trace, "Clear endless flag\n");
						isTaskStarted = true;
						isNeverEndedTask = false;
						break;
					}
					case ExecuteType_Stop:
					default:
						DebugModuleTrace(DL_Trace, "Stop execute\n");
						isNeverEndedTask = false;
						isTaskStarted = false;

						isTaskStopped = true;
						break;
				}
				break;
			}
			case Task_t::StopAction:
			default:
			{
				DebugModuleTrace(DL_Trace, "Another stop execute\n");
				isNeverEndedTask = false;
				isTaskStarted = false;
				isTaskStopped = true;
				break;
			}
		}
	}

	if(isTaskStarted)
	{
		IsConnectNeed = true;
		IsCloseNeed = false;
		NeverEndedTask = isNeverEndedTask;
		Events::CreateEvent(Events::ServerStartTask);
	}
	if(isTaskStopped)
	{
		IsConnectNeed = isTaskStarted;
		NeverEndedTask = false;

		if(IsConnectNeed == false)
		{
			if(State == TaskEGTSState_t::StartConnect || State == TaskEGTSState_t::WaitConnect)
			{
				Reset();
			}
			else
			{
				IsCloseNeed = true;
				DebugModuleTrace(DL_Data, "Start collect data\n");
			}
		}
		else
			IsCloseNeed = false;
	}

}


/****************************************************************************
 *
 *
 * FROM OLD SERVER!!!!!!!!!!!!!!!
 * @name Do
 * @brief Обработка текущего состояния протокола
 *
 * @param none
 * @return none
 ***************************************************************************/
void ServerEGTSProtocol::Do()
{
	CheckMessage();
	CheckTimer();

	if(TaskEGTSState_t::Online <= State && State <=TaskEGTSState_t::WaitMFlagClear)
	{
		if(!ExchangePort->IsConnected())
		{
			DebugModuleTrace(DL_Data, "Port %d lost...\n", ExchangePort->IsConnected());
			if(IsConnectNeed || NeverEndedTask)
			{
				ExchangePort->StartConnect();
				State = TaskEGTSState_t::StartConnect;
			}
			else
				Reset();
		}
	}

	if(RtmBin2_SendCounter != 0)
	{
		if(RtmBin2_SendTimer.IsExpired())
		{
			SendParamsToBin2();
			RtmBin2_SendTimer.StartMs(Timeout::SEND_BIN2_PERIOD);
			RtmBin2_SendCounter--;
		}
	}


	switch(State)
	{
		case TaskEGTSState_t::Idle:
		{
			if(NeverEndedTask)
				IsConnectNeed = true;

			if(IsConnectNeed)
			{
				State = TaskEGTSState_t::StartConnectInit;
				TaskTimer.StartMs(1000); // EGTSServer::Timeout::RESPONSE_TIMEOUT);
			}
		}
		break;

		case TaskEGTSState_t::StartConnectInit:
		{
			if(TaskTimer.IsExpired())
			{
				DebugModuleTrace(DL_Trace, "Start task\n");
				ServerConnectSettings_t ServerConnectSettings;
				//Read config data for a having ObjectNumber for EGTS (ReadData() with FieldNumber = 2)
				Memory.ConfigFile.ReadData((uint8_t*)&ServerConnectSettings, ConfigField::ServerConnectSettings, 2);
				EGTSParams.Number = ServerConnectSettings.ObjectId;

				// Выбор канала связи для текущего подключения
			#if defined(__TCP_MULTIPLEXER__)
				ExchangePort = Multiplexer::Multiplexer_C::GetInstance(this);
			#else
				ExchangePort = GprsPort_C::GetInstance(this);
			#endif // defined(__TCP_MULTIPLEXER__)

				DebugModuleTrace(DL_Data, "Use port 0x%08X\n", ExchangePort);


				TaskTimer.StartMs(Timeout::MAX_SERVER_CONNECTION_TIME);
				if(ExchangePort == nullptr)
				{
					DebugModuleTrace(DL_Trace, "Exchange port not available. Close task\n");
					Reset();
				}
				else
					State = TaskEGTSState_t::StartConnect;
			}
			break;
		}


		case TaskEGTSState_t::StartConnect:
		{
			if(ExchangePort->Use(this))
			{
				ExchangePort->StartConnect();
				State = TaskEGTSState_t::WaitConnect;
			}
			else
			{
				DebugModuleTrace(DL_Trace, "ExchangePort not available\n");
				State = TaskEGTSState_t::ErrorExchange;
			}

			break;
		}
		case TaskEGTSState_t::WaitConnect:
		{
			if(ExchangePort->IsConnected())
			{
				DebugModuleTrace(DL_Trace, "Connect ok!\n");

#if defined(__EGTS_STATISTIC__)
				Statistic.ConnectCounter++;
#endif // defined(__EGTS_STATISTIC__)
				if(this->Binding(ExchangePort))
				{
					RepeateCounter = 0;
					State = TaskEGTSState_t::Auth_TermIdent;
//					State = TaskEGTSState_t::Auth_AuthInfo;

					// Нумерация начинается с 1 для каждого сеанса обмена
					PID_Counter = 1;
					IsSendOk = false;
				}
				else
				{
					Reset();
					break;
				}
			}
			if(!ExchangePort->IsStartedConnect())
			{
				DebugModuleTrace(DL_Trace, "Port error! Close task\n");
				Reset();
				break;
			}
			break;
		}

		case TaskEGTSState_t::WaitDisconnect:
		{
			if(ExchangeTimer.IsExpired())
			{
				if(RepeateCounter < EGTS::Constants::ChannelCloseRetry)
				{
					ExchangePort->CloseConnect();
					ExchangeTimer.StartMs(EGTS::Timeout::ChannelClose);
					TaskTimer.StartMs(EGTS::Timeout::ChannelClose + 5000);
					RepeateCounter++;
				}
				else
					Reset();
			}
			else
			{
				if(!ExchangePort->IsConnected())
				{
					DebugModuleTrace(DL_Data, "Disconnected\n");
					if(IsConnectNeed || NeverEndedTask)
					{
						ExchangePort->StartConnect();
						State = TaskEGTSState_t::StartConnect;
					}
				}
			}
			break;
		}
		case TaskEGTSState_t::Auth_TermIdent:
		{
			SendIdent();
			ExchangeTimer.StartMs(Timeout::TL_RESPONSE_TO);
			State = TaskEGTSState_t::Auth_TermIdentWaitAck;
			break;
		}


		case TaskEGTSState_t::Auth_TermIdentWaitAck:
		{
			if(IsSendOk)
			{
				RepeateCounter = 0;
				DebugModuleTrace(DL_Data, "TERM_IDENT ack\n");
				IsSendOk = false;

#if defined(__EGTS_EXTRA_AUTH__)
				if(UseExtendedAuthentication)
				{
					DebugModuleTrace(DL_Data, "Start extend AUTH\n");
					State = TaskEGTSState_t::Auth_TermIdentOk;
					ExchangeTimer.StartMs(Timeout::EGTS_SL_NOT_AUTH_TO);
					break;
				}
#endif // defined(__EGTS_EXTRA_AUTH__)

				DebugModuleTrace(DL_Data, "Authentification is OK\n");
				State = TaskEGTSState_t::StartOnline;
				TaskTimer.StartMs(Timeout::EXCHANGE_INACTIVE_TIMEOUT);
			}
			else
			{
				if(ExchangePort->IsConnected() || ExchangePort->IsPaused())
				{
					if(ExchangeTimer.IsExpired())
					{
						if(RepeateCounter < Constants::AuthenticationRetry)
						{
							RepeateCounter++;
							State = TaskEGTSState_t::Auth_TermIdent;
						}
						else
						{
							DebugModuleTrace(DL_Data, "Repeate counter error!\n");
							State = TaskEGTSState_t::WaitDisconnect;
							ExchangeTimer.Reset();
							RepeateCounter = 0;
						}
					}
				}
				else
					State = TaskEGTSState_t::WaitConnect;
			}

			break;
		}

#if defined(__EGTS_EXTRA_AUTH__)
		case TaskEGTSState_t::Auth_TermIdentOk:
		{
			if(ExchangeTimer.IsExpired())
			{
				// Принудительная отправка имеющихся данных для авторизации
				State = TaskEGTSState_t::Auth_AuthInfo;
			}
			break;
		}
		case TaskEGTSState_t::Auth_AuthInfo:
		{
#if defined(__EGTS_CRYPTO__)
			// Шифрование начинает применяться с этого момента
			Memory.ConfigFile.ReadData(&UseEncryption, ConfigField::EgtsEncryptType);

			if(UseEncryption)
			{
				DebugModuleTrace(DL_Data, "ENCRYPTION ENABLE\n");
			}
#endif // defined(__EGTS_CRYPTO__)
			SendAuthenticationInfo();
			State = TaskEGTSState_t::Auth_AuthInfoWaitAck;
			ExchangeTimer.StartMs(Timeout::TL_RESPONSE_TO);
			break;
		}
		case TaskEGTSState_t::Auth_AuthInfoWaitAck:
		{
			if(IsSendOk)
			{
				RepeateCounter = 0;
				IsSendOk = false;

				DebugModuleTrace(DL_Data, "Await server AUTH result...\n");
				State = TaskEGTSState_t::Auth_ResultWait;
				ExchangeTimer.StartMs(Timeout::EGTS_SL_NOT_AUTH_TO);
				TaskTimer.StartMs(Timeout::EXCHANGE_INACTIVE_TIMEOUT);
			}
			else
			{
				if(ExchangePort->IsConnected() || ExchangePort->IsPaused())
				{
					if(ExchangeTimer.IsExpired())
					{
						if(RepeateCounter < Constants::AuthenticationRetry)
						{
							RepeateCounter++;
							State = TaskEGTSState_t::Auth_TermIdent;
						}
						else
						{
							DebugModuleTrace(DL_Data, "Repeate counter error!\n");
							State = TaskEGTSState_t::WaitDisconnect;
							ExchangeTimer.Reset();
							RepeateCounter = 0;
						}
					}
				}
				else
					State = TaskEGTSState_t::WaitConnect;
			}
			break;
		}
		case TaskEGTSState_t::Auth_ResultWait:
		{
			if(IsSendOk)
			{
				State = TaskEGTSState_t::Auth_ResultSendAck;
				ExchangeTimer.Reset();
			}
			if(ExchangeTimer.IsExpired())
			{
				State = TaskEGTSState_t::StartOnline;
			}
			break;
		}
		case TaskEGTSState_t::Auth_ResultSendAck:
		{
			if(ExchangeTimer.IsExpired())
			{
				if(RepeateCounter <= Constants::TL_RESEND_ATTEMPTS)
				{
					if(SendResponse(Service_t::AUTH_SERVICE, CachePacketId))
					{
						State = TaskEGTSState_t::StartOnline;
					}
					else
					{
						DebugModuleTrace(DL_Trace, "Send error, retry %d\n", RepeateCounter);
						RepeateCounter++;
						ExchangeTimer.StartMs(1000);
					}
				}
				else
					Reset();
			}
			break;
		}

#endif // defined(__EGTS_EXTRA_AUTH__)


		case TaskEGTSState_t::StartOnline:
		{
			uint32_t currentRecordCount = History.GetDeltaIndexEGTS();
			uint32_t dataSendTimeout = 0;

			if(currentRecordCount == 0)
			{
				DebugModuleTrace(DL_Trace, "History is empty\n");
				ForceHistoryStatus = ForceState::Executed;
				dataSendTimeout = Timeout::FORCE_SEND_TIMEOUT;
			}
			else
			{
				ForceHistoryStatus = ForceState::ForceSend;
			}
			ExchangeTimer.StartMs(dataSendTimeout);
			MaxRecordCount = BUFFERED_RECORDS_NUMBER;
			State = TaskEGTSState_t::Online;
			RepeateCounter = 0;
			break;
		}
		case TaskEGTSState_t::Online:
		{
			if(IsDataReady() || IsCloseNeed)
			{
				if(ExchangePort->IsConnected())
				{
					if(Events::EventMemory.GetEGTSFlagMask() != 0 && !IsSendOk)
					{
						_LocalTraceDelimiter(DL_Data);
						DebugModuleTrace(DL_Trace, "Send FLAGS to EGTS\n");
						State = TaskEGTSState_t::SendMFlag;
					}
					else
					{
						_LocalTraceDelimiter(DL_Data);
						DebugModuleTrace(DL_Trace, "Start send data (delta %d)\n", History.GetDeltaIndexEGTS());
						IsSendOk = false;
						State = TaskEGTSState_t::DataExchange;
					}
				}
				else
				{
					if(ExchangePort->IsPaused())
					{
						DebugModuleTrace(DL_ExtendedData, "Gprs on pause, wait channel\n");
						ExchangeTimer.StartMs(Timeout::RETRY_TIMEOUT);
					}
					else
					{
						DebugModuleTrace(DL_Trace, "ExchangePort disconnected, error on execution\n");
						State = TaskEGTSState_t::WaitDisconnect;
						ExchangeTimer.Reset();
						RepeateCounter = 0;
					}
				}
			}
			else
			{
				if(IsConnectNeed == false || ExchangeTimer.IsExpired())
				{
					DebugModuleTrace(DL_Trace, "Executed, wait\n");
					State = TaskEGTSState_t::Executed;
					ExchangeTimer.StartMs(Timeout::FORCE_SEND_TIMEOUT);
				}
			}
			break;
		}
		// Передача данных на сервер
		case TaskEGTSState_t::DataExchange:
		{
			if(SendHistory())
			{
				ExchangeTimer.StartMs(Timeout::RESPONSE_TIMEOUT);
				TaskTimer.ProlongateMs(Timeout::EXCHANGE_INACTIVE_TIMEOUT);
				State = TaskEGTSState_t::WaitDataAck;
				if(ForceHistoryStatus == ForceState::ForceCreateHistoryBlock)
				{
					ForceHistoryStatus = ForceState::WaitAck;
					if(!NeverEndedTask)
						IsConnectNeed = false;
				}
			}
			else
			{
				if(IsCloseNeed)
				{
					State = TaskEGTSState_t::CloseConnect;
				}
				else
				{
					ExchangeTimer.StartMs(Timeout::RESPONSE_TIMEOUT);
					State = TaskEGTSState_t::WaitDataAck;
				}
			}
			break;
		}
		case TaskEGTSState_t::WaitDataAck:
		{
			if(IsSendOk)
			{
				GuardConnect::SendReport(GuardConnect::Report_t::FinishOperation);
				RepeateCounter = 0;
				DebugModuleTrace(DL_Data, "Data ack\n");
#if defined(__SUPPORT_MULTI_MODEM__)
				ExchangePort->ConfirmConnection();
#endif // defined(__SUPPORT_MULTI_MODEM__)
				DeliveredData();
				IsSendOk = false;

				if(IsConnectNeed)
				{
					State = TaskEGTSState_t::Online;
					ExchangeTimer.StartMs(Timeout::FORCE_SEND_TIMEOUT);
				}
				else
					State = TaskEGTSState_t::CloseConnect;
			}
			else
			{
				if(ExchangeTimer.IsExpired())
				{
					if(RepeateCounter < Constants::DataSendRetry)
					{
						RepeateCounter++;
						DebugModuleTrace(DL_Data, "Ack timeout expired\n");
						State = TaskEGTSState_t::Online;
					}
					else
					{
						DebugModuleTrace(DL_Data, "Too much unreciprocated messages!\n");
						Events::CreateEvent(Events::ServerStopTask);
						State = TaskEGTSState_t::WaitDisconnect;
						ExchangeTimer.Reset();
						RepeateCounter = 0;
					}
				}
			}
			break;
		}
		case TaskEGTSState_t::SendMFlag:
		{
			if(SendMFlag())
			{
				TaskTimer.ProlongateMs(Timeout::EXCHANGE_INACTIVE_TIMEOUT);
				ExchangeTimer.StartMs(Timeout::RESPONSE_TIMEOUT);
				State = TaskEGTSState_t::WaitMFlagClear;
			}
			else
			{
				ExchangeTimer.StartMs(Timeout::RETRY_TIMEOUT);
				State = TaskEGTSState_t::Online;
			}
			break;
		}
		case TaskEGTSState_t::WaitMFlagClear:
		{
			if(IsSendOk)
			{
				RepeateCounter = 0;
				DebugModuleTrace(DL_Data, "Flag ack\n");
				DeliveredData();
#if defined(__SUPPORT_MULTI_MODEM__)
				ExchangePort->ConfirmConnection();
#endif // defined(__SUPPORT_MULTI_MODEM__)
				IsSendOk = false;
				State = TaskEGTSState_t::Online;
			}
			else
			{
				if(ExchangeTimer.IsExpired())
				{
					if(RepeateCounter < Constants::DataSendRetry)
					{
						RepeateCounter++;
						State = TaskEGTSState_t::SendMFlag;
					}
					else
					{
						DebugModuleTrace(DL_Data, "Repeate counter error!\n");
						Events::CreateEvent(Events::ServerStopTask);
						State = TaskEGTSState_t::WaitDisconnect;
						ExchangeTimer.Reset();
						RepeateCounter = 0;
					}
				}
			}

			break;
		}
		case TaskEGTSState_t::ErrorExchange:
		{
			Reset();
			break;
		}
		case TaskEGTSState_t::CloseConnect:
		{
			Reset();
			break;
		}
		case TaskEGTSState_t::WaitCloseConnect:
		{
			if(!ExchangePort->IsConnected())
			{
				State = TaskEGTSState_t::Idle;
			}
			if(TaskTimer.IsExpired())
				State = TaskEGTSState_t::ErrorExchange;
			break;
		}
		case TaskEGTSState_t::Executed:
		{
			//! Проверка необходимости продолжения обмена
			if(IsDataReady())
			{
				State = TaskEGTSState_t::Online;
			}
			else
			{
				if(IsConnectNeed == false)
					State = TaskEGTSState_t::CloseConnect;
			}
			break;
		}
		default:
			break;
	}
}


/****************************************************************************
 * @name Executed
 * @brief Получить статус "выполнено"
 * Возвращает true, если протокол выполнил свою работу полностью
 *
 * @param none
 * @return none
 ***************************************************************************/
bool ServerEGTSProtocol::Executed()
{
	bool executed = false;

	if((ForceHistoryStatus == ForceState::Executed) && (State >= TaskEGTSState_t::StartOnline))
		executed = true;
	else
	{
		if(State == TaskEGTSState_t::Idle || State == TaskEGTSState_t::Executed)
			executed = true;
	}

	return executed;
}


/****************************************************************************
 * @name ErrorExecute
 * @brief Проверка на ошибку исполнения задачи
 *
 * @param none
 * @return true, если при работе задачи возникла ошибка
 ***************************************************************************/
bool ServerEGTSProtocol::ErrorExecute()
{
	return State == TaskEGTSState_t::ErrorExchange;
}


/****************************************************************************
 * @name Init
 * @brief Инициализация задачи
 *
 * @param none
 * @return none
 ***************************************************************************/
void ServerEGTSProtocol::Init()
{
	Reset();
#if defined(__EGTS_STATISTIC__)
	InitStatisticData();
#endif // defined(__EGTS_STATISTIC__)

#if defined(__EGTS_CRYPTO__)
//	Memory.ConfigFile.ReadData(&UseEncryption, ConfigField::EgtsEncryptType);
	UseEncryption = false;	// Шифрование включается после авторизации
#endif // defined(__EGTS_CRYPTO__)

#if defined(__EGTS_EXTRA_AUTH__)
	UseExtendedAuthentication = true;
#endif // defined(__EGTS_EXTRA_AUTH__)
};


/****************************************************************************
 * @name InitStatisticData
 * @brief Инициализация данных счетчиков статистики
 * Выполняется проверка наличия и поиск последних значений счетчиков статистики,
 * сохраненных в истории прибора.
 *
 * @param none
 * @return none
 ***************************************************************************/
void ServerEGTSProtocol::InitStatisticData()
{
	Memory.ConfigFile.ReadData(&UseStatistic, ConfigField::EgtsUseStatistic);
	uint8_t lastRecord[RubberHistory::Constant::CacheSize];
	History.ReadRecord(UniqueRecordID.New, lastRecord, RubberHistory::Constant::CacheSize);

	if(!History.GetDataFromRecord(UniqueRecordID.New, RubberHistory::RecordId::EgtsRecOk, &Statistic.TotalConfirmed))
		Statistic.TotalConfirmed = 0;

	if(!History.GetDataFromRecord(UniqueRecordID.New, RubberHistory::RecordId::EgtsRecFault, &Statistic.Unsent))
		Statistic.Unsent = 0;

	if(!History.GetDataFromRecord(UniqueRecordID.New, RubberHistory::RecordId::EgtsConnectCount, &Statistic.ConnectCounter))
		Statistic.ConnectCounter = 0;
}


ProcessCode_t ServerEGTSProtocol::ParseAuthServiceSubrecords(uint8_t *Data, uint16_t DataSize)
{
	ProcessCode_t ProcessCode = ProcessCode_t::NO_ACK;

	SubrecordSSLP * subrecord = (SubrecordSSLP *)Data;
	uint16_t subrecordSize = 0;

	DebugTrace(DL_Data, "AUTH_SERVICE srt %d\n", subrecord->Header.SRT);
	switch (subrecord->Header.SRT)
	{
		case AUTH_SERVICE::SubrecordType::EGTS_SR_AUTH_PARAMS:
		{
			uint8_t Flags = *(subrecord->Data);
			DebugTrace(DL_Data, "flags0x%02X\n", *(uint8_t *)(subrecord->Header.SRD));

			subrecordSize = 1;
			// Проверка наличия полей PKL, PBK
			if(Flags & 0x04)
			{
				uint16_t PublicKeyLength = 0;
				memcpy(&PublicKeyLength, ((uint8_t *)subrecord) + subrecordSize, sizeof(PublicKeyLength));
				subrecordSize += sizeof(PublicKeyLength) + PublicKeyLength;
			}

			// Проверка наличия поля ISL
			if(Flags & 0x08)
			{
				// Размер поля ISL фиксирован и равен 2 байтам
				subrecordSize += 2;
			}

			// Проверка наличия поля MZS
			if(Flags & 0x10)
			{
				// Размер поля MZS фиксирован и равен 2 байтам
				subrecordSize += 2;
			}

			// Проверка наличия полей SS, Delimiter
			if(Flags & 0x20)
			{
				char *ServerSequenceString = ((char *)subrecord) + subrecordSize;
				subrecordSize += strnlen(ServerSequenceString, 255);
				// Учет поля Delimiter
				subrecordSize += 1;
			}
			// Проверка наличия полей EXP, Delimiter
			if(Flags & 0x40)
			{
				char *ExpString = ((char *)subrecord) + subrecordSize;
				subrecordSize += strnlen(ExpString, 255);
				// Учет поля Delimiter
				subrecordSize += 1;
			}

			if(subrecordSize > DataSize)
			{
				DebugModuleTrace(DL_Data, "Wrong message!\n");
				ProcessCode = ProcessCode_t::INC_DATAFORM;
				return ProcessCode;
			}

			ProcessCode = ProcessCode_t::OK;
#if defined(__EGTS_CRYPTO__)
			if((Flags & 0x03) == 0x01)
			{
				// Шифрование начинает применяться с этого момента
				Memory.ConfigFile.ReadData(&UseEncryption, ConfigField::EgtsEncryptType);

				if(UseEncryption)
				{
					DebugModuleTrace(DL_Data, "ENCRYPTION ENABLE\n");
				}
				else
				{
					DebugModuleTrace(DL_Data, "ENCRYPTION request, but disable on device\n");
					ProcessCode = ProcessCode_t::UNS_PROTOCOL;
					return ProcessCode;
				}
			}
#endif // defined(__EGTS_CRYPTO__)

			break;
		}
		case AUTH_SERVICE::SubrecordType::EGTS_SR_RECORD_RESPONSE:
		{
			Response_t responseData;
			memcpy(&responseData, subrecord->Data, sizeof(responseData));

			if(responseData.RPID == CachePacketId && responseData.PR == ProcessCode_t::OK)
				IsSendOk = true;
			break;
		}
		case AUTH_SERVICE::SubrecordType::EGTS_SR_RESULT_CODE:
		{

			if(State == TaskEGTSState_t::Auth_TermIdentOk)
				State = TaskEGTSState_t::Auth_AuthInfo;
//			else

			break;
		}
		default:
			break;
	}

	return ProcessCode;
}


ProcessCode_t ServerEGTSProtocol::ParseTeledataServiceSubrecords(uint8_t *Data, uint16_t DataSize)
{
	return ProcessCode_t::OK;
}




void ServerEGTSProtocol::ParseRecord(uint8_t *SdrData, uint16_t SdrLength)
{
	// Размер разобранных данных
	uint16_t parsedPacketSize = 0;
	uint8_t *currentRecordData = SdrData;

	while(parsedPacketSize < SdrLength)
	{
		// Защита от переполнения количества пришедших записей
		if(ParsedRecordCount >= Constants::MaxReceivedRecodsInPacket)
		{
			ParsedRecordCount -= 1;
			ProcessCodes[ParsedRecordCount].ResultCode = ProcessCode_t::NO_RES_AVAIL;
			break;
		}


		HeaderSdrMinimal_t Header;
		memcpy(&Header, currentRecordData, sizeof(Header));

		// Полный размер записи - вместе с заголовком
		uint16_t RecordSize = 0;
		// Проверка наличия необязательных полей
		if(Header.RFL & 0x01)
			RecordSize += 4;	// OID
		if(Header.RFL & 0x02)
			RecordSize += 4;	// EVID
		if(Header.RFL & 0x04)
			RecordSize += 4;	// TM

		DebugTrace(DL_Data, "APP_DATA len %d, num %d\n", Header.RL, Header.RN);

		uint8_t *subrecordData = currentRecordData + sizeof(HeaderSdrMinimal_t);

		RecordSize += sizeof(HeaderSdrMinimal_t) + Header.RL;

		if(parsedPacketSize + RecordSize > SdrLength)
		{
			DebugModuleTrace(DL_Trace, "Parsed packet with wrong size!\n");
			break;
		}

		Service_t SourceService = *(Service_t*)(currentRecordData + 5);
		switch (SourceService)
		{
			case Service_t::AUTH_SERVICE:
			{
				ProcessCodes[ParsedRecordCount].RecordNumber = Header.RN;
				ProcessCodes[ParsedRecordCount].ResultCode = ParseAuthServiceSubrecords(subrecordData, Header.RL);
				break;
			}
			case Service_t::TELEDATA_SERVICE:
			{
				ProcessCodes[ParsedRecordCount].RecordNumber = Header.RN;
				ProcessCodes[ParsedRecordCount].ResultCode = ParseTeledataServiceSubrecords(subrecordData, Header.RL);
				break;
			}
			default:
				ProcessCodes[ParsedRecordCount].RecordNumber = Header.RN;
				ProcessCodes[ParsedRecordCount].ResultCode = ProcessCode_t::SRVC_NFOUND;
				break;
		}

		ParsedRecordCount++;
		parsedPacketSize += RecordSize;
		currentRecordData += RecordSize;
	}

}

/****************************************************************************
 * @name Parser
 * @brief Разбор входящего пакета
 *
 *
 * @param CurrentPacketType - тип пакета транспортного уровня
 * @param Data - данные пакета
 * @param DataSize - размер пакета для разбора
 * @return none
 ***************************************************************************/
void ServerEGTSProtocol::Parser(HeaderTransport_t *PacketHeader, uint8_t *Data)
{
	uint16_t DataSize = PacketHeader->FDL;
	DebugTrace(DL_Data, "Packet #%d, type %d\n", PacketHeader->PID, PacketHeader->PT);
	switch(PacketHeader->PT)
	{
		case Transport::PacketType::RESPONSE:
		{
			Response_t responsePacket;
			memcpy(&responsePacket, Data, sizeof(responsePacket));
			DebugTrace(DL_Data, "Response to %d, status %d\n", responsePacket.RPID, responsePacket.PR);
			if(responsePacket.RPID == CachePacketId)
			{
				if(responsePacket.PR == ProcessCode_t::OK)
				{
					if(DataSize <= sizeof(responsePacket))
					{
						DebugTrace(DL_Data, "Simple response\n");
						IsSendOk = true;
					}
					else
					{
						DataSize -= sizeof(responsePacket);
						ParseRecord(Data + sizeof(responsePacket), DataSize);
					}
				}
			}
			break;
		}
		case Transport::PacketType::APPDATA:
		{
			ParseRecord(Data, DataSize);
			break;
		}
		case Transport::PacketType::SIGNED_APPDATA:
		{
			DebugModuleTrace(DL_Data, "SIGNED_APPDATA not supported at current firmware. Sorry...\n");
			break;
		}
		default:
			break;
	}
}


/****************************************************************************
 * @name Receive
 * @brief Прием входящего потока данных
 *
 * @param data - буфер входящего потока
 * @param dataSize - размер данных входящего потока
 * @return размер принятых данных
 ***************************************************************************/
uint32_t ServerEGTSProtocol::Receive(const void * data, uint32_t dataSize)
{
	uint32_t copiedDataSize = dataSize;
	uint32_t maxBufVolume = (uint32_t)(RxBuffer.size() - RxBufferLevel - 1);
	if(copiedDataSize > maxBufVolume)
		copiedDataSize = maxBufVolume;

	DebugModuleTrace(DL_Trace, "Receive packet");
	DebugTrace(DL_Data, " (%d bytes) :<", dataSize);
	DebugTraceAscii(DL_Data, data, dataSize);
	DebugTrace(DL_Data, ">");
	DebugTrace(DL_Trace, "\n");

	uint8_t* buffer = (uint8_t*) data;
	uint8_t data_size_loc = (uint8_t)copiedDataSize;

	if(!Find_start)
	{
		do
		{
			//EGTS_PT_RESPONSE packet start byte
			if(*buffer == Constants::ProtocolVersion)
			{
				Find_start = 1;
				break;
			}
			buffer++;
			data_size_loc--;
		}while (data_size_loc);
	}

	if(Find_start)
	{
		memcpy(&RxBuffer[RxBufferLevel], buffer, data_size_loc);
		RxBufferLevel += data_size_loc;

		// detect EGTS_PT_RESPONSE packet
		if(RxBufferLevel >= sizeof(HeaderTransport_t))
		{
			uint16_t FrameDataLength = (RxBuffer[6] << 8) + RxBuffer[5];
//			memcpy(&FrameDataLength, &RxBuffer[5], sizeof(FrameDataLength));
			if(RxBufferLevel >= sizeof(HeaderTransport_t) + FrameDataLength + Constants::SFRCSLength)
			{
				HeaderTransport_t Header;
				memcpy(&Header, RxBuffer.begin(), sizeof(HeaderTransport_t));
				// HL
				if(Header.HL == sizeof(HeaderTransport_t))
				{
					// PRV
					if(Header.PRV == Constants::ProtocolVersion)
					{
						// HCS
//						if(Header.HCS == CalcCRC8_31(RxBuffer.begin(), Header.HL - 1))
						uint8_t HCS = CalcCRC8_31(RxBuffer.begin(), Header.HL - 1);
						DebugModuleTrace(DL_Data, "HCS %04X\n", HCS);
						{
							// FDL
							if(Header.FDL != 0)
							{
								// SFRD (для APP_DATA), RPID (для APP_RESPONSE)
								uint8_t *PacketData = &RxBuffer.at(sizeof(Header));
								// SFRCS
								uint16_t SFRCS;
								memcpy(&SFRCS, PacketData + FrameDataLength, sizeof(SFRCS));
								SFRCS = Crc16(PacketData, FrameDataLength);
								DebugModuleTrace(DL_Data, "SFRCS %04X\n", SFRCS);

								{
									DebugModuleTrace(DL_Data, "Received response %d :<", Header.FDL);
									DebugTraceAscii(DL_Data, PacketData, Header.FDL);
									DebugTrace(DL_Data, ">\n");

									if(PID_Counter <= Header.PID)
										PID_Counter = Header.PID + 1;

#if defined(__EGTS_CRYPTO__)
									uint8_t EncryptionMode = (Header.Mask_1 >> 3) & 0x03;

									if(EncryptionMode != 0)
									{
										ExtendTime_t perfEncryption = *STime.GetFullTime();

										// Количество байт для шифрования должно быть кратно 8
										uint16_t decryptedDataSize = (Header.FDL + 7) & ~0x0007;
										Gost28147::Decrypt(PacketData, decryptedDataSize);

										ExtendTime_t deltaEncryption = *STime.GetFullTime();

										deltaEncryption = deltaEncryption - perfEncryption;
										DebugModuleTrace(DL_Data, "Encryption duration: %d.%03d\n", deltaEncryption.Second, deltaEncryption.Millisecond);

										DebugModuleTrace(DL_Data, "Decrypted response %d :<", decryptedDataSize);
										DebugTraceAscii(DL_Data, PacketData, decryptedDataSize);
										DebugTrace(DL_Trace, ">\n");
									}
#endif // defined(__EGTS_CRYPTO__)

									Parser(&Header, PacketData);
								}
							}
						}
					}
				}
				RxBufferLevel = 0;
				Find_start = false;
			}
		}
	}
	return copiedDataSize;
}


/**************************************************************************
 * @brief Сброс протокола в начальное состояние
 *
 * @param none
 * @return none
 **************************************************************************/
void ServerEGTSProtocol::Reset()
{
	DebugModuleTrace(DL_Trace, "Reset from %d, NE %d\n", State, NeverEndedTask);

	clock_t delayTimeout = 1000;
	if(TaskEGTSState_t::StartOnline < State && State < TaskEGTSState_t::ErrorExchange)
	{
		State = TaskEGTSState_t::WaitCloseConnect;
		delayTimeout = Timeout::ChannelClose;
	}
	else
		State = TaskEGTSState_t::Idle;

	TaskTimer.StartMs(delayTimeout);

	if(ExchangePort != NULL)
	{
		ExchangePort->CloseConnect();
	}

#if defined(__TCP_MULTIPLEXER__)
	Multiplexer::Multiplexer_C::FreeAllInstances(this);
#else
	if(ExchangePort != NULL)
		((GprsPort_C *)ExchangePort)->Free(this);
#endif // defined(__TCP_MULTIPLEXER__)

	SerialChannel_c::Reset();
	ServerExchangeProtocol::Reset();

	RxBufferLevel = 0;
	RxBuffer.fill(0);
	ForceHistoryStatus = ForceState::ForceSend;
	IsSendOk = false;
	Find_start = false;

	IsCloseNeed = false;
	IsConnectNeed = false;
}


uint16_t ServerEGTSProtocol::ReadStruct(void * Data, FieldId FieldType, uint16_t FieldNumber)
{
	uint16_t readedSize = 0;
	switch(FieldType)
	{
#if defined(__EGTS_STATISTIC__)
		case FieldId::StatisticEnable:
			*(uint8_t *)Data = UseStatistic;
			readedSize = 1;
			break;
		case FieldId::SendCommand:
		{
			*(uint8_t *)Data = RtmBin2_SendCounter;
			readedSize = 1;
			break;
		}
		case FieldId::StatisticContent:
		{
			*(uint8_t *)Data = Constants::StatisticNumber;		// const value - 7 значений
			readedSize = 1;
			break;
		}
		case FieldId::StatisticValue:
		{
			switch (FieldNumber)
			{
				// Счетчик 1 - CN100 - Количество подтвержденных записей
				case 0:
				{
					if(History.ExtGetDataFromRecordBuffer(RubberHistory::RecordId::HRID::EgtsRecOk, Data))
						readedSize = 4;
					break;
				}
				//	Счетчик 2 - CN101 - Количество потерянных записей;
				case 1:
				{
					if(History.ExtGetDataFromRecordBuffer(RubberHistory::RecordId::HRID::EgtsRecFault, Data))
						readedSize = 4;
					break;
				}
				//	Счетчик 3 - CN102 - Количество соединений с сервером;
				case 2:
				{
					if(History.ExtGetDataFromRecordBuffer(RubberHistory::RecordId::HRID::EgtsConnectCount, Data))
						readedSize = 4;
					break;
				}
				//	Счетчик 4 - CN103 - Индекс самой новой записи;
				case 3:
				{
					readedSize = sizeof(UniqueRecordID.New);
					memcpy(Data, &UniqueRecordID.New, readedSize);
					break;
				}
				//	Счетчик 5 - CN104 - Индекс самой старой записи;
				case 4:
				{
					readedSize = sizeof(UniqueRecordID.Old);
					memcpy(Data, &UniqueRecordID.Old, readedSize);
					break;
				}
				//	Счетчик 6 - CN105, CN106 - Дата и время самой старой записи;
				case 5:
				{
					time_t oldRecordTime = History.GetRecordTime(UniqueRecordID.Old);
					readedSize = sizeof(oldRecordTime);
					memcpy(Data, &oldRecordTime, readedSize);
					break;
				}
				//	Счетчик 7 - CN110, CN111 - Номер передаваемой записи.
				case 6:
				{
					uint32_t currentSendIndex = History.FindIndexFirstUnsentRecordEGTS(); // OlderUnsentRecordIndexEGTS;
					readedSize = sizeof(currentSendIndex);
					memcpy(Data, &currentSendIndex, readedSize);
					break;
				}
				default:
					break;
			}
			break;
		}
#endif // defined(__EGTS_STATISTIC__)

#if defined(__EGTS_CRYPTO__)
		case FieldId::CryptoEnable:
		{
			readedSize = Memory.ConfigFile.ReadData(Data, ConfigField::EgtsEncryptType, FieldNumber);
			break;
		}
		case FieldId::CryptoKey:
		{
			readedSize = Memory.CertificateStorage.ReadData(Data, AuthenticityCertificate::FieldID_t::Gost28147_PrivateKey, FieldNumber);
			break;
		}
		case FieldId::CryptoTable:
		{
			readedSize = Memory.CertificateStorage.ReadData(Data, AuthenticityCertificate::FieldID_t::Gost28147_ShiftTable, FieldNumber);
			break;
		}
#endif // defined(__EGTS_CRYPTO__)

		default:
			break;
	}

	return readedSize;

}


uint16_t ServerEGTSProtocol::WriteStruct(const void * Data, FieldId FieldType, uint16_t FieldNumber)
{
	(void)FieldNumber;
	uint16_t writedSize = 0;
	switch(FieldType)
	{
#if defined(__EGTS_STATISTIC__)
		case FieldId::StatisticEnable:
		{
			UseStatistic = *(bool *)Data;
			Memory.ConfigFile.WriteData(&UseStatistic, ConfigField::EgtsUseStatistic);
			writedSize = 1;
			break;
		}
		case FieldId::StatisticValue:
		{
			uint32_t newValue;
			memcpy(&newValue, Data, sizeof(newValue));

			if(newValue == 0)
			{
				writedSize = sizeof(newValue);
				switch (FieldNumber)
				{
					case 0:
						Statistic.TotalConfirmed = 0;
						break;
					case 1:
						Statistic.Unsent = 0;
						break;
					case 2:
						Statistic.ConnectCounter = 0;
						break;
					default:
						writedSize = 0;
						break;
				}
			}
			break;
		}
		case FieldId::SendCommand:
		{
			uint8_t newValue = *(uint8_t *)Data;

			TEmbeddedUnit currentBufferUnit = rtm_common::CurrentBuffer->GetDestinationUnitID();
			if(newValue == 0)
			{
				// Only port-owner can stop data flow
				if(currentBufferUnit == RtmBin2_DestinationUnit)
				{
					RtmBin2_SendCounter = 0;
					RtmBin2_SendTimer.Reset();

					DebugModuleTrace(DL_Data, "Send stat stopped by %d module\n", RtmBin2_SendCounter, RtmBin2_DestinationUnit);
				}
				else
				{
					DebugModuleTrace(DL_Data, "Unauthorized stop send stat by %d\n", currentBufferUnit);
				}
			}
			else
			{
				RtmBin2_SendCounter = newValue;
				RtmBin2_DestinationUnit = currentBufferUnit;
				RtmBin2_DestinationAddress = rtm_common::CurrentBuffer->SourceAddress;

				DebugModuleTrace(DL_Data, "Start send stat on %d sec\n", RtmBin2_SendCounter);
			}
			writedSize = 1;
			break;
		}
#endif // defined(__EGTS_STATISTIC__)

#if defined(__EGTS_CRYPTO__)
		case FieldId::CryptoEnable:
		{
			memcpy(&UseEncryption, Data, sizeof(UseEncryption));
			writedSize = Memory.ConfigFile.WriteData(Data, ConfigField::EgtsEncryptType, FieldNumber);
			break;
		}
		case FieldId::CryptoKey:
		{
			writedSize = Memory.CertificateStorage.WriteData(Data, AuthenticityCertificate::FieldID_t::Gost28147_PrivateKey, FieldNumber);
			break;
		}
		case FieldId::CryptoTable:
		{
			writedSize = Memory.CertificateStorage.WriteData(Data, AuthenticityCertificate::FieldID_t::Gost28147_ShiftTable, FieldNumber);
			break;
		}
#endif // defined(__EGTS_CRYPTO__)

		default:
			break;
	}

	return writedSize;
}




/****************************************************************************
 * @name DeliveredData
 * @brief Обслуживание доставки данных на сервер
 *
 * @param none
 * @return none
 ***************************************************************************/
void ServerEGTSProtocol::DeliveredData()
{
	switch(State)
	{
		case TaskEGTSState_t::WaitMFlagClear:
		{
			DebugModuleTrace(DL_ExtendedData, "Clear MFLAG 0x%04X\n", CurFlagMask);
			Events::EventMemory.ClearFlagEGTS(CurFlagMask);
			break;
		}
		case TaskEGTSState_t::WaitDataAck:
		{
			DebugModuleTrace(DL_Trace, "FHS %d\n", ForceHistoryStatus);

			if(ForceHistoryStatus == ForceState::WaitAck)
			{
				DebugModuleTrace(DL_Trace, "Send executed\n");
				ForceHistoryStatus = ForceState::Executed;

				if(!NeverEndedTask)
					IsConnectNeed = false;

				MaxRecordCount = History.GetCurrentRecordLimit();
			}

			// Не отмечается переданной запись с номером 31, если она передавалась
			if(BufferedRecordCount > BUFFERED_RECORDS_NUMBER)
			{
				BufferedRecordCount = BUFFERED_RECORDS_NUMBER;
				History.LastPositionChecked();
			}

			for(uint16_t count = 0; count < BufferedRecordCount; count++)
			{
				DebugModuleTrace(DL_ExtendedData, "Mark %X record as send\n", BufferedRecordIndex[count]);
				History.MarkRecordSendedEGTS(BufferedRecordIndex[count]);
			}

#if defined(__EGTS_STATISTIC__)
			Statistic.TotalConfirmed += BufferedRecordCount;
#endif // defined(__EGTS_STATISTIC__)

			BufferedRecordCount = 0;
			break;
		}
		default:
		{
			DebugModuleTrace(DL_Data, "Unexpected ack!\n");
			Reset();
			break;
		}

	}
}


/****************************************************************************
 * @name TimersCheck
 * @brief Проверка таймеров текущей задачи.
 * При необходимости - переключение состояния алгоритма.
 *
 * @param none
 * @return none
 ***************************************************************************/
void ServerEGTSProtocol::CheckTimer()
{
	if(TaskEGTSState_t::StartConnect < State && State < TaskEGTSState_t::WaitCloseConnect)
	{
		if(TaskTimer.IsExpired())
		{
			DebugModuleTrace(DL_Data, "Task timer is elapsed!\n");
			Reset();
		}
	}
}





#if defined(__EGTS_STATISTIC__)
/**
 * Self-sender of current values
 */
void ServerEGTSProtocol::SendParamsToBin2()
{
	rtm_common::rtm_bin_v2::Command_t *commandData = (rtm_common::rtm_bin_v2::Command_t *)sprintbuf;

	commandData->Header.CommandId = rtm_common::CommandCodes::Enum::EGTS_STAT_VALUE;
	commandData->Header.Recepient = RtmBin2_DestinationAddress;
	commandData->Header.Function = rtm_common::rtm_bin::Function::WriteStruct_Unaccepted;
	commandData->Header.StructCount = Constants::StatisticNumber;


	uint32_t sendStatisticData[Constants::StatisticNumber];
	sendStatisticData[0] = Statistic.TotalConfirmed;
	sendStatisticData[1] = Statistic.Unsent;
	sendStatisticData[2] = Statistic.ConnectCounter;

	sendStatisticData[3] = UniqueRecordID.New;
	sendStatisticData[4] = UniqueRecordID.Old;

	sendStatisticData[5] = History.GetRecordTime(UniqueRecordID.Old);
	sendStatisticData[6] = History.FindIndexFirstUnsentRecordEGTS();

	DebugModuleTrace(DL_Data, "old record %d time %d\n", UniqueRecordID.Old, sendStatisticData[5]);
	uint16_t dataSize = sizeof(sendStatisticData);
	memcpy(&commandData->Data, &sendStatisticData[0], dataSize);

	commandData->Header.DataSize = dataSize;

	dataSize += sizeof(commandData->Header);

	Task_t SendCurrentStatisticData(RtmBin2_DestinationUnit, Task_t::CommandExecution, dataSize, 1000);
	TaskBuffer.SetTask(&SendCurrentStatisticData, commandData);
}

#endif // defined(__EGTS_STATISTIC__)



bool ServerEGTSProtocol::SendResponse(Service_t Service, uint16_t ConfirmedPacketID)
{
	DebugModuleTrace(DL_Data, "Send SR_RESPONSE, Service %d, transport number %d, packet id %d\n", Service, PID_Counter, RecordNumber);
//	bool result = false;

	// Заполнение данных отправляемого пакета - сначала формирование записей
	TransportPacket_t *OutgoingPacketBuffer = (TransportPacket_t *) sprintbuf;
	// Заполнение данных отправляемых записей - сначала формирование подзаписей
	RecordSSLP *currentRecord = OutgoingPacketBuffer->Record;

	AUTH_SERVICE::SR_RECORD_RESPONSE responseSubrecord;
	responseSubrecord.ConfirmedRecordNumber = ConfirmedPacketID;
	responseSubrecord.RecordStatus = 0;

	uint16_t recordSize = sizeof(responseSubrecord);
	memcpy(currentRecord->Subrecord, &responseSubrecord, recordSize);

//	SendCache[0].RecordNumber = RecordNumber;
//	SendCache[0].HistoryRecNum = RubberHistory::INDEX_NOT_EXIST;
	CacheSdrCount = 1;

	HeaderSDR_t Header;
	Header.RL = recordSize;
	Header.RN = RecordNumber++;
	Header.RFL = 0x85;
	Header.OID = EGTSParams.Number;
	Header.TM = ConvertTime(0);
	Header.SST = Service_t::AUTH_SERVICE;
	Header.RST = Service_t::AUTH_SERVICE;

	memcpy(&currentRecord->Header, &Header, sizeof(Header));
	recordSize += sizeof(Header);


	CacheService = Service_t::AUTH_SERVICE;
	CachePacketId = PID_Counter;

	// TODO проверить вычисление размера
	if(SendPacket(OutgoingPacketBuffer, Transport::PacketType::RESPONSE, recordSize))
		return true;

	DebugModuleTrace(DL_Trace, "Error on AUTH_PARAM sending!\n");
//	Reset();

	return false;
}


#if defined(__EGTS_EXTRA_AUTH__)
/****************************************************************************
 * @name SendAuthenticationInfo
 * @brief Отправка записи подтверждения EGTS_SR_RECORD_RESPONSE сервиса AUTH_SERVICE
 *
 * @param none
 * @return none
 ***************************************************************************/
bool ServerEGTSProtocol::SendAuthenticationInfo()
{
//	bool result = false;

	// Заполнение данных отправляемого пакета - сначала формирование записей
	TransportPacket_t *OutgoingPacketBuffer = (TransportPacket_t *) sprintbuf;
	// Заполнение данных отправляемых записей - сначала формирование подзаписей
	RecordSSLP *currentRecord = OutgoingPacketBuffer->Record;

	SubrecordSSLP *AuthSubrecord = currentRecord->Subrecord;
	AuthSubrecord->Header.SRT = AUTH_SERVICE::SubrecordType::EGTS_SR_AUTH_INFO;

	uint16_t recordSize = 0;
	char * userName = (char *) AuthSubrecord->Data;
	strncpy(userName, Constants::DefaultUserName, 32);
	uint16_t stringSize = strnlen(userName, 32);
	if(stringSize > 32)
		stringSize = 32;
	userName[stringSize] = 0;

	char *userPassword = userName + stringSize + 1;
	strncpy(userPassword, Constants::DefaultUserPassword, 32);
	stringSize = strnlen(userPassword, 32);
	if(stringSize > 32)
		stringSize = 32;
	userPassword[stringSize] = 0;

	recordSize = (userPassword + stringSize + 1) - (char *) AuthSubrecord->Data;

	AuthSubrecord->Header.SRL = recordSize;

	recordSize += sizeof(AuthSubrecord->Header);

	SendCache[0].RecordNumber = RecordNumber;
	SendCache[0].HistoryRecNum = RubberHistory::INDEX_NOT_EXIST;
	CacheSdrCount = 1;

	HeaderSDR_t Header;
	Header.RL = recordSize;
	Header.RN = RecordNumber++;
	Header.RFL = 0x85;
	Header.OID = EGTSParams.Number;
	Header.TM = ConvertTime(0);
	Header.SST = Service_t::AUTH_SERVICE;
	Header.RST = Service_t::AUTH_SERVICE;

	memcpy(&currentRecord->Header, &Header, sizeof(Header));

	recordSize += sizeof(Header);

	CacheService = Service_t::AUTH_SERVICE;
	CachePacketId = PID_Counter;

	if(SendPacket(OutgoingPacketBuffer, Transport::PacketType::APPDATA, recordSize))
		return true;

	DebugModuleTrace(DL_Trace, "Error on AUTH_INFO sending!\n");
	Reset();

	return false;
}
#endif // defined(__EGTS_EXTRA_AUTH__)


void HistoryCallBack(RubberHistory::RecordId::HRID RecordFieldId)
{
	switch(RecordFieldId)
	{
		case RubberHistory::RecordId::EgtsRecOk:
			History.SetDataByHRID(RubberHistory::RecordId::EgtsRecOk, &EGTSProtocol.Statistic.TotalConfirmed);
			break;
		case RubberHistory::RecordId::EgtsRecFault:
			History.SetDataByHRID(RubberHistory::RecordId::EgtsRecFault, &EGTSProtocol.Statistic.Unsent);
			break;
		case RubberHistory::RecordId::EgtsConnectCount:
			History.SetDataByHRID(RubberHistory::RecordId::EgtsConnectCount, &EGTSProtocol.Statistic.ConnectCounter);
			break;
		default:
			break;
	}
}


}  // namespace EGTS

#pragma pack(pop)

//#endif // defined(__EGTS_SERVER)
/****************************************************************************
 *								Конец файла									*
 ****************************************************************************/

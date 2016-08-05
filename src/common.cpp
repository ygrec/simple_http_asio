/*
 * common.cpp
 *
 *  Created on: 24 июля 2016 г.
 *      Author: Игорь
 */

#include "common.hpp"

#include <boost/date_time.hpp>
#include <string>
#include <array>



void PrintTimeStamp()
{
	boost::date_time::winapi::SYSTEMTIME currentSystemTime;
	boost::date_time::winapi::GetSystemTime(&currentSystemTime);
	std::cout << "Time: " << std::setfill ('0') << currentSystemTime.wHour << ":" << std::setw(2) << currentSystemTime.wMinute << \
			":" << std::setw(2) << currentSystemTime.wSecond << "." << std::setw(3) << currentSystemTime.wMilliseconds << " ";
}


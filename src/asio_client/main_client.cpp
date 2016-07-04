/*
 * main.cpp
 *
 *  Created on: 30 θώνÿ 2016 γ.
 *      Author: i.brickii
 */

#include "client.hpp"
#include <boost/asio/io_service.hpp>

using namespace boost;
using namespace asio;

io_service service;

void connect_handler(const boost::system::error_code & ec)
 {
    // here we know we connected successfully
    // if ec indicates success
}


int main(int argc, char* argv[])
{
//	HANDLE file = ::CreateFile("readme.txt", GENERIC_READ, 0, 0,
//	OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,0);
//	windows::random_access_handle h(service, file);
//	streambuf buf;
//	read_at(h, 256, buf, transfer_exactly(128));
//	std::istream in(&buf);
//	std::string line;
//	std::getline(in, line);
//	std::cout << "first line: " << line << std::endl;

	ip::tcp::endpoint ep( ip::address::from_string("127.0.0.1"), 2001);
	ip::tcp::socket sock(service);
	sock.async_connect(ep, connect_handler);
	service.run();
}


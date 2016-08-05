///*
// * client.cpp
// *
// *  Created on: 30 ���� 2016 �.
// *      Author: i.brickii
// */
//
//#include "client.hpp"
//
//void talk_to_svr::start(ip::tcp::endpoint ep) {
//	sock_.async_connect(ep, MEM_FN1(on_connect, _1));
//}
//
//static ptr talk_to_svr::start(ip::tcp::endpoint ep, const std::string & username) {
//	ptr new_(new talk_to_svr(username));
//	new_->start(ep);
//	return new_;
//}
//
//
//void talk_to_svr::stop() {
//	if (!started_)
//		return;
//	std::cout << "stopping " << username_ << std::endl;
//	started_ = false;
//	sock_.close();
//}
//
//bool talk_to_svr::started() {
//	return started_;
//}
//
//void talk_to_svr::on_connect(const error_code & err) {
//	if ( !err) do_write("login " + username_ + "\n");
//	else stop();
//}
//
//void on_read(const error_code & err, size_t bytes) {
//	if (err)
//		stop();
//	if (!started())
//		return;
//	// process the msg
//	std::string msg(read_buffer_, bytes);
//	if (msg.find("login ") == 0)
//		on_login();
//	else if (msg.find("ping") == 0)
//		on_ping(msg);
//	else if (msg.find("clients ") == 0)
//		on_clients(msg);
//	else
//		std::cerr << "invalid msg " << msg << std::endl;
//}
//
//
//void on_login() {
//	std::cout << username_ << " logged in" << std::endl;
//	do_ask_clients();
//}
//
//
//void on_ping(const std::string & msg) {
//	std::istringstream in(msg);
//	std::string answer;
//	in >> answer >> answer;
//	if (answer == "client_list_changed")
//		do_ask_clients();
//	else
//		postpone_ping();
//}
//
//
//void on_clients(const std::string & msg) {
//	std::string clients = msg.substr(8);
//	std::cout << username_ << ", new client list:" << clients;
//	postpone_ping();
//}
//
//void do_ping() {
//	do_write("ping\n");
//}
//
//
//void postpone_ping() {
//	// note: even though the server wants a ping every 5 secs, we randomly
//	// don't ping that fast - so that the server will randomly disconnect us
//	int millis = rand() % 7000;
//	std::cout << username_ << " postponing ping " << millis << " millis"
//			<< std::endl;
//	timer_.expires_from_now(boost::posix_time::millisec(millis));
//	timer_.async_wait(MEM_FN(do_ping));
//}
//
//
//void do_ask_clients() {
//	do_write("ask_clients\n");
//}
//
//
//void on_write(const error_code & err, size_t bytes) {
//	do_read();
//}
//
//
//void do_read() {
//	async_read(sock_, buffer(read_buffer_), MEM_FN2(read_complete, _1, _2),
//			MEM_FN2(on_read, _1, _2));
//}
//
//
//void do_write(const std::string & msg) {
//	if (!started())
//		return;
//	std::copy(msg.begin(), msg.end(), write_buffer_);
//	sock_.async_write_some(buffer(write_buffer_, msg.size()),
//			MEM_FN2(on_write, _1, _2));
//}
//
//
//size_t read_complete(const boost::system::error_code & err, size_t bytes) {
//	if (err)
//		return 0;
//	bool found = std::find(read_buffer_, read_buffer_ + bytes, '\n')
//			< read_buffer_ + bytes;
//	// we read one-by-one until we get to enter, no buffering
//	return found ? 0 : 1;
//}

#include "client.hpp"

extern io_service service;

ip::tcp::endpoint talk_to_svr::CacheEndPoint;
uint32_t talk_to_svr::MaxThreadCount = 0;

talk_to_svr::talk_to_svr(const std::string & username) :
		sock_(service), started_(true), username_(username), timer_(service)
{
	connectionAttemtpCounter = 0;
	CurrentThreadNumber = MaxThreadCount++;
	std::cout << "Create " << CurrentThreadNumber << std::endl;
}

void talk_to_svr::start()
{
	PrintTimeStamp();
	std::cout << "Th " << CurrentThreadNumber << " - start connect" <<std::endl;
	sock_.async_connect(CacheEndPoint, MEM_FN1(on_connect, _1));
}

talk_to_svr::ptr talk_to_svr::start(ip::tcp::endpoint ep, const std::string & username)
{
	ptr new_(new talk_to_svr(username));
	CacheEndPoint = ep;
	new_->start();
	return new_;
}

void talk_to_svr::stop()
{
	if (!started_)
		return;
	std::cout << "stopping " << username_ << std::endl;
	started_ = false;
	sock_.close();
}

bool talk_to_svr::started()
{
	return started_;
}

void talk_to_svr::on_connect(const error_code & err)
{
	if (!err)
	{
		PrintTimeStamp();
		std::cout << "Th " << CurrentThreadNumber << ", Connection OK" << std::endl;
		do_write("login " + username_ + "\n");
	}
	else
	{
		PrintTimeStamp();
		std::cout << "Th " << CurrentThreadNumber << ", Connection attempt " << connectionAttemtpCounter
				<< " unsuccesfully" << std::endl;
		if (connectionAttemtpCounter < MaxConnectionAttempt)
		{
			connectionAttemtpCounter++;
			int millis = (rand() + 4000) % 4000;
			std::cout << "Start await for " << millis << " ms."
					<< std::endl;
			timer_.expires_from_now(boost::posix_time::millisec(millis));
//                timer_.async_wait( MEM_FN(do_ping));
			timer_.async_wait(boost::bind(&talk_to_svr::start, shared_from_this()));
//        		sock_.async_connect(CacheEndPoint, MEM_FN1(on_connect,_1));
		}
//        	stop();
	}
}

void talk_to_svr::on_read(const error_code & err, size_t bytes)
{
	if (err)
		stop();
	if (!started())
		return;
	// process the msg
	std::string msg(read_buffer_, bytes);
	if (msg.find("login ") == 0)
		on_login();
	else if (msg.find("ping") == 0)
		on_ping(msg);
	else if (msg.find("clients ") == 0)
		on_clients(msg);
	else
		std::cerr << "invalid msg " << msg << std::endl;
}

void talk_to_svr::on_login()
{
	std::cout << username_ << " logged in" << std::endl;
	do_ask_clients();
}
void talk_to_svr::on_ping(const std::string & msg)
{
	std::istringstream in(msg);
	std::string answer;
	in >> answer >> answer;
	if (answer == "client_list_changed")
		do_ask_clients();
	else
		postpone_ping();
}
void talk_to_svr::on_clients(const std::string & msg)
{
	std::string clients = msg.substr(8);
	std::cout << username_ << ", new client list:" << clients;
	postpone_ping();
}

void talk_to_svr::do_ping()
{
	do_write("ping\n");
}

void talk_to_svr::postpone_ping()
{
	// note: even though the server wants a ping every 5 secs, we randomly
	// don't ping that fast - so that the server will randomly disconnect us
	int millis = rand() % 7000;
	std::cout << username_ << " postponing ping " << millis << " millis"
			<< std::endl;
	timer_.expires_from_now(boost::posix_time::millisec(millis));
	timer_.async_wait(MEM_FN(do_ping));
}

void talk_to_svr::do_ask_clients()
{
	do_write("ask_clients\n");
}

void talk_to_svr::on_write(const error_code & err, size_t bytes)
{
	do_read();
}
void talk_to_svr::do_read()
{
	async_read(sock_, buffer(read_buffer_), MEM_FN2(read_complete, _1, _2),
			MEM_FN2(on_read, _1, _2));
}
void talk_to_svr::do_write(const std::string & msg)
{
	if (!started())
		return;

	PrintTimeStamp();
	std::cout << "Th " << CurrentThreadNumber << ", client " << username_ << " send message \"" << msg << "\"" << std::endl;
	std::copy(msg.begin(), msg.end(), write_buffer_);
	sock_.async_write_some(buffer(write_buffer_, msg.size()),
			MEM_FN2(on_write, _1, _2));
}

size_t talk_to_svr::read_complete(const boost::system::error_code & err, size_t bytes)
{
	if (err)
		return 0;
	bool found = std::find(read_buffer_, read_buffer_ + bytes, '\n')
			< read_buffer_ + bytes;
	// we read one-by-one until we get to enter, no buffering
	return found ? 0 : 1;
}


/*
 * client.cpp
 *
 *  Created on: 30 θώνÿ 2016 γ.
 *      Author: i.brickii
 */


//#include "client.hpp"


//
//void on_connect(const error_code & err)
//{
//	if ( !err) do_write("login " + username_ + "\n");
//	else stop();
//}
//void on_read(const error_code & err, size_t bytes)
//{
//	if ( err) stop();
//	if ( !started() ) return;
//	// process the msg
//	std::string msg(read_buffer_, bytes);
//	if ( msg.find("login ") == 0) on_login();
//	else if ( msg.find("ping") == 0) on_ping(msg);
//	else if ( msg.find("clients ") == 0) on_clients(msg);
//}
//void on_login()
//{
//	do_ask_clients();
//}
//void on_ping(const std::string & msg)
//{
//	std::istringstream in(msg);
//	std::string answer;
//	in >> answer >> answer;
//	if ( answer == "client_list_changed") do_ask_clients();
//	else postpone_ping();
//}
//void on_clients(const std::string & msg)
//{
//	std::string clients = msg.substr(8);
//	std::cout << username_ << ", new client list:" << clients ;
//	postpone_ping();
//}

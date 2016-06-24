################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../connection.cpp \
../connection_manager.cpp \
../main.cpp \
../mime_types.cpp \
../reply.cpp \
../request_handler.cpp \
../request_parser.cpp \
../server.cpp 

OBJS += \
./connection.o \
./connection_manager.o \
./main.o \
./mime_types.o \
./reply.o \
./request_handler.o \
./request_parser.o \
./server.o 

CPP_DEPS += \
./connection.d \
./connection_manager.d \
./main.d \
./mime_types.d \
./reply.d \
./request_handler.d \
./request_parser.d \
./server.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '



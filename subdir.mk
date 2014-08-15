#
#  pcap2sipp     - tool for generating the sipp scenario, injection file and RTP packets 
#  that are needed to run a sipp test that simulates the behavior from a given pcap trace
#  Copyright (c) 2012 Catalina Oancea
# 
#  * * BEGIN LICENCE * * *
# 
#  This file is part of pcap2sipp
# 
#  pcap2sipp is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
# 
#  pcap2sipp is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with pcap2sipp.  If not, see <http://www.gnu.org/licenses/>.
# 
#  * * END LICENCE * * *
# 
# 
################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
nodes.c \
pcap2sipp.c \
strings.c 

OBJS += \
nodes.o \
pcap2sipp.o \
strings.o 

C_DEPS += \
nodes.d \
pcap2sipp.d \
strings.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: %.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -ggdb3 -DDEBUG -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
#	gcc -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

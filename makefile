#
# pcap2sipp     - tool for generating the sipp scenario, injection file and RTP packets 
# that are needed to run a sipp test that simulates the behavior from a given pcap trace
# Copyright (c) 2012 Catalina Oancea
#
# * * BEGIN LICENCE * * *
#
# This file is part of pcap2sipp
#
# pcap2sipp is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# pcap2sipp is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pcap2sipp.  If not, see <http://www.gnu.org/licenses/>.
#
# * * END LICENCE * * *
#
#
################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: pcap2sipp

# Tool invocations
pcap2sipp: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	gcc -o"pcap2sipp" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(OBJS)$(C_DEPS)$(EXECUTABLES) pcap2sipp
	-@echo ' '

.PHONY: all clean dependents
.SECONDARY:

-include ../makefile.targets

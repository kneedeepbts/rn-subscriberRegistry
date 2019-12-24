#
# Copyright 2008, 2009 Free Software Foundation, Inc.
# Copyright 2011, 2012, 2014 Range Networks, Inc.
#
# This software is distributed under the terms of the GNU Public License.
# See the COPYING file in the main directory for details.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

include $(top_srcdir)/Makefile.common

# AM_CPPFLAGS = $(STD_DEFINES_AND_INCLUDES)
# AM_CXXFLAGS = -Wall -O3 -g -ldl -lpthread -lsqlite3

#EXTRA_DIST = \
#	example.config \
#	README.common

noinst_LTLIBRARIES = libfixmes.la

libfixmes_la_CXXFLAGS = $(AM_CXXFLAGS) -O3 -lsqlite3
libfixmes_la_SOURCES = \
	sqlite3util.cpp \
	Utils.cpp

noinst_HEADERS = \
	sqlite3util.h \
	Utils.h

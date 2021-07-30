//
// StatusMessageSerializer.h
//
// Package: Generated
// Module:  TypeSerializer
//
// This file has been generated.
// Warning: All changes to this will be lost when the file is re-generated.
//
// Copyright (c) 2016-2020, Applied Informatics Software Engineering GmbH.
// All rights reserved.
// 
// SPDX-License-Identifier: GPL-3.0-only
//


#ifndef TypeSerializer_IoT_DeviceStatus_StatusMessage_INCLUDED
#define TypeSerializer_IoT_DeviceStatus_StatusMessage_INCLUDED


#include "IoT/DeviceStatus/DeviceStatusService.h"
#include "Poco/RemotingNG/TypeSerializer.h"


namespace Poco {
namespace RemotingNG {


template <>
class TypeSerializer<IoT::DeviceStatus::StatusMessage>
{
public:
	static void serialize(const std::string& name, const IoT::DeviceStatus::StatusMessage& value, Serializer& ser)
	{
		using namespace std::string_literals;
		
		ser.serializeStructBegin(name);
		serializeImpl(value, ser);
		ser.serializeStructEnd(name);
	}

	static void serializeImpl(const IoT::DeviceStatus::StatusMessage& value, Serializer& ser)
	{
		using namespace std::string_literals;
		
		static const std::string REMOTING__NAMES[] = {"acknowledgeable"s,"acknowledged"s,"id"s,"messageClass"s,"source"s,"status"s,"text"s,"timestamp"s,""s};
		TypeSerializer<bool >::serialize(REMOTING__NAMES[0], value.acknowledgeable, ser);
		TypeSerializer<bool >::serialize(REMOTING__NAMES[1], value.acknowledged, ser);
		TypeSerializer<Poco::Int64 >::serialize(REMOTING__NAMES[2], value.id, ser);
		TypeSerializer<std::string >::serialize(REMOTING__NAMES[3], value.messageClass, ser);
		TypeSerializer<std::string >::serialize(REMOTING__NAMES[4], value.source, ser);
		TypeSerializer<int >::serialize(REMOTING__NAMES[5], static_cast<int>(value.status), ser);
		TypeSerializer<std::string >::serialize(REMOTING__NAMES[6], value.text, ser);
		TypeSerializer<Poco::DateTime >::serialize(REMOTING__NAMES[7], value.timestamp, ser);
	}

};


} // namespace RemotingNG
} // namespace Poco


#endif // TypeSerializer_IoT_DeviceStatus_StatusMessage_INCLUDED


//
// MessagePublishedEventSerializer.h
//
// Package: Generated
// Module:  TypeSerializer
//
// This file has been generated.
// Warning: All changes to this will be lost when the file is re-generated.
//
// Copyright (c) 2015-2020, Applied Informatics Software Engineering GmbH.
// All rights reserved.
// 
// SPDX-License-Identifier: GPL-3.0-only
//


#ifndef TypeSerializer_IoT_MQTT_MessagePublishedEvent_INCLUDED
#define TypeSerializer_IoT_MQTT_MessagePublishedEvent_INCLUDED


#include "IoT/MQTT/PropertyDeserializer.h"
#include "IoT/MQTT/PropertySerializer.h"
#include "IoT/MQTT/Types.h"
#include "Poco/RemotingNG/TypeSerializer.h"


namespace Poco {
namespace RemotingNG {


template <>
class TypeSerializer<IoT::MQTT::MessagePublishedEvent>
{
public:
	static void serialize(const std::string& name, const IoT::MQTT::MessagePublishedEvent& value, Serializer& ser)
	{
		using namespace std::string_literals;
		
		ser.serializeStructBegin(name);
		serializeImpl(value, ser);
		ser.serializeStructEnd(name);
	}

	static void serializeImpl(const IoT::MQTT::MessagePublishedEvent& value, Serializer& ser)
	{
		using namespace std::string_literals;
		
		static const std::string REMOTING__NAMES[] = {"properties"s,"reasonCode"s,"token"s,""s};
		TypeSerializer<std::vector < IoT::MQTT::Property > >::serialize(REMOTING__NAMES[0], value.properties, ser);
		TypeSerializer<int >::serialize(REMOTING__NAMES[1], static_cast<int>(value.reasonCode), ser);
		TypeSerializer<int >::serialize(REMOTING__NAMES[2], value.token, ser);
	}

};


} // namespace RemotingNG
} // namespace Poco


#endif // TypeSerializer_IoT_MQTT_MessagePublishedEvent_INCLUDED


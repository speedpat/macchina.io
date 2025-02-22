//
// IndicationSerializer.h
//
// Package: Generated
// Module:  TypeSerializer
//
// This file has been generated.
// Warning: All changes to this will be lost when the file is re-generated.
//
// Copyright (c) 2017-2020, Applied Informatics Software Engineering GmbH.
// All rights reserved.
// 
// SPDX-License-Identifier: GPL-3.0-only
//


#ifndef TypeSerializer_IoT_BtLE_Indication_INCLUDED
#define TypeSerializer_IoT_BtLE_Indication_INCLUDED


#include "IoT/BtLE/Peripheral.h"
#include "Poco/RemotingNG/TypeSerializer.h"


namespace Poco {
namespace RemotingNG {


template <>
class TypeSerializer<IoT::BtLE::Indication>
{
public:
	static void serialize(const std::string& name, const IoT::BtLE::Indication& value, Serializer& ser)
	{
		using namespace std::string_literals;
		
		ser.serializeStructBegin(name);
		serializeImpl(value, ser);
		ser.serializeStructEnd(name);
	}

	static void serializeImpl(const IoT::BtLE::Indication& value, Serializer& ser)
	{
		using namespace std::string_literals;
		
		static const std::string REMOTING__NAMES[] = {"data"s,"handle"s,""s};
		TypeSerializer<std::vector < char > >::serialize(REMOTING__NAMES[0], value.data, ser);
		TypeSerializer<Poco::UInt16 >::serialize(REMOTING__NAMES[1], value.handle, ser);
	}

};


} // namespace RemotingNG
} // namespace Poco


#endif // TypeSerializer_IoT_BtLE_Indication_INCLUDED


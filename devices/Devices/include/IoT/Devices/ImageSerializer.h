//
// ImageSerializer.h
//
// Package: Generated
// Module:  TypeSerializer
//
// This file has been generated.
// Warning: All changes to this will be lost when the file is re-generated.
//
// Copyright (c) 2014-2020, Applied Informatics Software Engineering GmbH.
// All rights reserved.
// 
// SPDX-License-Identifier: GPL-3.0-only
//


#ifndef TypeSerializer_IoT_Devices_Image_INCLUDED
#define TypeSerializer_IoT_Devices_Image_INCLUDED


#include "IoT/Devices/Camera.h"
#include "Poco/RemotingNG/TypeSerializer.h"


namespace Poco {
namespace RemotingNG {


template <>
class TypeSerializer<IoT::Devices::Image>
{
public:
	static void serialize(const std::string& name, const IoT::Devices::Image& value, Serializer& ser)
	{
		using namespace std::string_literals;
		
		ser.serializeStructBegin(name);
		serializeImpl(value, ser);
		ser.serializeStructEnd(name);
	}

	static void serializeImpl(const IoT::Devices::Image& value, Serializer& ser)
	{
		using namespace std::string_literals;
		
		static const std::string REMOTING__NAMES[] = {"encoding"s,"height"s,"image"s,"step"s,"width"s,""s};
		TypeSerializer<std::string >::serialize(REMOTING__NAMES[0], value.encoding, ser);
		TypeSerializer<int >::serialize(REMOTING__NAMES[1], value.height, ser);
		TypeSerializer<Poco::SharedPtr < std::vector < char > > >::serialize(REMOTING__NAMES[2], value.image, ser);
		TypeSerializer<int >::serialize(REMOTING__NAMES[3], value.step, ser);
		TypeSerializer<int >::serialize(REMOTING__NAMES[4], value.width, ser);
	}

};


} // namespace RemotingNG
} // namespace Poco


#endif // TypeSerializer_IoT_Devices_Image_INCLUDED


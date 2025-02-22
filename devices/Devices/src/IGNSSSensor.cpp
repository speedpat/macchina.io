//
// IGNSSSensor.cpp
//
// Library: IoT/Devices
// Package: Generated
// Module:  IGNSSSensor
//
// This file has been generated.
// Warning: All changes to this will be lost when the file is re-generated.
//
// Copyright (c) 2014-2020, Applied Informatics Software Engineering GmbH.
// All rights reserved.
// 
// SPDX-License-Identifier: GPL-3.0-only
//


#include "IoT/Devices/IGNSSSensor.h"


namespace IoT {
namespace Devices {


IGNSSSensor::IGNSSSensor():
	IoT::Devices::IDevice(),
	positionLost(),
	positionUpdate()
{
}


IGNSSSensor::~IGNSSSensor()
{
}


bool IGNSSSensor::isA(const std::type_info& otherType) const
{
	std::string name(type().name());
	return name == otherType.name();
}


const Poco::RemotingNG::Identifiable::TypeId& IGNSSSensor::remoting__typeId()
{
	static const std::string REMOTING__TYPE_ID("IoT.Devices.GNSSSensor");
	return REMOTING__TYPE_ID;
}


const std::type_info& IGNSSSensor::type() const
{
	return typeid(IGNSSSensor);
}


} // namespace Devices
} // namespace IoT


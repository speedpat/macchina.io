//
// IMQTTClient.cpp
//
// Library: IoT/MQTT
// Package: Generated
// Module:  IMQTTClient
//
// This file has been generated.
// Warning: All changes to this will be lost when the file is re-generated.
//
// Copyright (c) 2015-2020, Applied Informatics Software Engineering GmbH.
// All rights reserved.
// 
// SPDX-License-Identifier: GPL-3.0-only
//


#include "IoT/MQTT/IMQTTClient.h"


namespace IoT {
namespace MQTT {


IMQTTClient::IMQTTClient():
	Poco::OSP::Service(),
	connectionClosed(),
	connectionEstablished(),
	connectionLost(),
	disconnected(),
	messageArrived(),
	messageDelivered(),
	messagePublished()
{
}


IMQTTClient::~IMQTTClient()
{
}


bool IMQTTClient::isA(const std::type_info& otherType) const
{
	std::string name(type().name());
	return name == otherType.name();
}


const Poco::RemotingNG::Identifiable::TypeId& IMQTTClient::remoting__typeId()
{
	static const std::string REMOTING__TYPE_ID("IoT.MQTT.MQTTClient");
	return REMOTING__TYPE_ID;
}


const std::type_info& IMQTTClient::type() const
{
	return typeid(IMQTTClient);
}


} // namespace MQTT
} // namespace IoT


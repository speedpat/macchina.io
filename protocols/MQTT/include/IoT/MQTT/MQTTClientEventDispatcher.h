//
// MQTTClientEventDispatcher.h
//
// Library: IoT/MQTT
// Package: Generated
// Module:  MQTTClientEventDispatcher
//
// This file has been generated.
// Warning: All changes to this will be lost when the file is re-generated.
//
// Copyright (c) 2015-2020, Applied Informatics Software Engineering GmbH.
// All rights reserved.
// 
// SPDX-License-Identifier: GPL-3.0-only
//


#ifndef IoT_MQTT_MQTTClientEventDispatcher_INCLUDED
#define IoT_MQTT_MQTTClientEventDispatcher_INCLUDED


#include "IoT/MQTT/MQTTClientRemoteObject.h"
#include "Poco/RemotingNG/EventDispatcher.h"


namespace IoT {
namespace MQTT {


class MQTTClientEventDispatcher: public Poco::RemotingNG::EventDispatcher
	/// The interface for MQTT clients.
	///
	/// Implementations are expected to receive their client ID and
	/// server URI via an implementation defined configuration mechanism.
	/// Once configured, a MQTTClient always uses the same client ID and
	/// connects to the same server. A MQTT client should automatically
	/// attempt to reconnect if the connection to the server is lost.
	///
	/// A single client instance can either support MQTT version 3.1/3.1.1
	/// or version 5. Which MQTT version is supported by the client is
	/// determined when configuring the client.
	///
	/// Users of the class must call the appropriate methods supporting
	/// the client's configured MQTT version.
{
public:
	MQTTClientEventDispatcher(MQTTClientRemoteObject* pRemoteObject, const std::string& protocol);
		/// Creates a MQTTClientEventDispatcher.

	virtual ~MQTTClientEventDispatcher();
		/// Destroys the MQTTClientEventDispatcher.

	void event__connectionClosed(const void* pSender);

	void event__connectionEstablished(const void* pSender, const IoT::MQTT::ConnectionEstablishedEvent& data);

	void event__connectionLost(const void* pSender, const IoT::MQTT::ConnectionLostEvent& data);

	void event__disconnected(const void* pSender, const IoT::MQTT::DisconnectedEvent& data);

	void event__messageArrived(const void* pSender, const IoT::MQTT::MessageArrivedEvent& data);

	void event__messageDelivered(const void* pSender, const IoT::MQTT::MessageDeliveredEvent& data);

	void event__messagePublished(const void* pSender, const IoT::MQTT::MessagePublishedEvent& data);

	virtual const Poco::RemotingNG::Identifiable::TypeId& remoting__typeId() const;

private:
	void event__connectionClosedImpl(const std::string& subscriberURI);

	void event__connectionEstablishedImpl(const std::string& subscriberURI, const IoT::MQTT::ConnectionEstablishedEvent& data);

	void event__connectionLostImpl(const std::string& subscriberURI, const IoT::MQTT::ConnectionLostEvent& data);

	void event__disconnectedImpl(const std::string& subscriberURI, const IoT::MQTT::DisconnectedEvent& data);

	void event__messageArrivedImpl(const std::string& subscriberURI, const IoT::MQTT::MessageArrivedEvent& data);

	void event__messageDeliveredImpl(const std::string& subscriberURI, const IoT::MQTT::MessageDeliveredEvent& data);

	void event__messagePublishedImpl(const std::string& subscriberURI, const IoT::MQTT::MessagePublishedEvent& data);

	static const std::string DEFAULT_NS;
	MQTTClientRemoteObject* _pRemoteObject;
};


inline const Poco::RemotingNG::Identifiable::TypeId& MQTTClientEventDispatcher::remoting__typeId() const
{
	return IMQTTClient::remoting__typeId();
}


} // namespace MQTT
} // namespace IoT


#endif // IoT_MQTT_MQTTClientEventDispatcher_INCLUDED

